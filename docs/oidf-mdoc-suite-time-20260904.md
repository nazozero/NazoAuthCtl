# OIDF Suite mdoc document-signer validity diagnosis (2026-09-04)

## Scope and status

This is a local, read-only diagnosis of the failure in the OID4VP plan
`openid4vc-vp-p040`, Suite module record `MsWChpvjsqb2Jzm`. It caused the
plan's early termination. The accompanying `ValidateDirectPostResponse`
WARNING is a consequence of that termination, not the primary defect. This
note does not change NazoAuth or NazoAuthCtl runtime code, the OIDF
Conformance Suite, or any retained Suite record. It has not been sent upstream.

The preserved sample and its certificate material are private local evidence.
This note intentionally records only times, public certificate metadata, and
hashes; it does not reproduce the credential, bearer token, or test secrets.

## Affected official instance

An authenticated `GET https://www.certification.openid.net/api/server` returned:

| Field | Value |
| --- | --- |
| version | `5.2.4` |
| tag | `release-v5.2.4` |
| revision | `ab35a8d` |
| build_time | `2026-08-27T08:28:36Z` |

The inspected local upstream checkout is `c902d643e61dbb21f107d0e8eacdd8fb25fa2fed`
on `master`, dated `2026-09-01`. It is source evidence for the generation paths,
not a claim that the deployed official instance is exactly that revision.

## Reproduced facts

The private p040 `DeviceResponse` contains one `IssuerSigned` document. Its MSO
and embedded `issuerAuth` document-signer (DS) certificate show:

| Item | UTC value |
| --- | --- |
| MSO `validityInfo.signed` | `2026-09-04T03:29:21Z` |
| MSO `validityInfo.validFrom` | `2026-09-04T03:29:21Z` |
| DS certificate `notBefore` | `2026-09-04T04:24:21Z` |
| DS certificate `notAfter` | `2026-12-03T04:29:21Z` |
| Suite response / DS-mint reference time | `2026-09-04T04:29:21Z` |

The DS is a non-self-signed EC P-256 certificate issued by the supplied matrix
IACA. Its serial is `4B9C682506FF30C1A469B999D6B8F673823B8FAB`, and its SHA-256
fingerprint is
`1B:EC:F4:A5:44:6B:8D:52:27:F6:03:BD:BB:CB:1B:61:01:22:8F:75:49:B2:A8:98:8C:8B:04:1A:4C:BC:14:F9`.
The leaf extracted from `issuerAuth` has that same fingerprint.

The supplied IACA verifies the path at the response time. It does not make the
leaf valid at the MSO signing time.

```text
# At MSO signed/validFrom = 2026-09-04T03:29:21Z
openssl verify -CAfile matrix-iaca.pem -attime 1788492561 suite-signer.pem
# error 9 at 0 depth lookup: certificate is not yet valid

# At response/DS-mint time = 2026-09-04T04:29:21Z
openssl verify -CAfile matrix-iaca.pem -attime 1788496161 suite-signer.pem
# suite-signer.pem: OK
```

The same IACA and leaf verify with the ordinary current-time `openssl verify`
after `notBefore`; this isolates the issue to validation time rather than the
trust anchor, chain signature, key usage, or certificate identity.

## Source-level cause

The p040 plan is the Suite-as-wallet presentation path. In the source snapshot:

1. [`CreateMdocCredential.java`](https://gitlab.com/openid/conformance-suite/-/blob/c902d643e61dbb21f107d0e8eacdd8fb25fa2fed/src/main/java/net/openid/conformance/condition/as/CreateMdocCredential.java#L33)
   calls `TestAppUtils.initialise()` before creating the `DeviceResponse`
   (lines 33-35).
2. [`TestAppUtils.kt`](https://gitlab.com/openid/conformance-suite/-/blob/c902d643e61dbb21f107d0e8eacdd8fb25fa2fed/src/main/kotlin/com/android/identity/testapp/TestAppUtils.kt#L215)
   obtains `TestKeysAndCerts.documentSignerKey` and provisions the document
   (lines 215-226). The provisioned mdoc uses `signedAt = now - 1.hours` and
   `validFrom = now - 1.hours` (lines 358-361).
3. [`TestKeysAndCerts.kt`](https://gitlab.com/openid/conformance-suite/-/blob/c902d643e61dbb21f107d0e8eacdd8fb25fa2fed/src/main/kotlin/net/openid/conformance/util/TestKeysAndCerts.kt#L143)
   creates that runtime DS certificate with `notBefore = now - 5 minutes`
   (lines 143-145).

The observed times match those expressions exactly: the MSO is one hour before
the response/mint reference, while the DS has only a five-minute backdate. The
DS is therefore 55 minutes in the future at the MSO's stated signing time.

The VCI issuer helper has a related boundary: `VciMdocUtils.kt` rounds
`signedAt`/`validFrom` down to the hour (lines 74-87). A one-hour DS backdate
also covers that path; the current five-minute window does not cover the
worst-case hour rounding.

## ISO requirement and NazoAuth signing-time validation

ISO/IEC 18013-5:2021 section 9.3.1 requires an mdoc reader to validate the
MSO-header certificate, then validate `ValidityInfo`. Its fifth step expressly
requires that the `signed` date be within that certificate's validity period;
it separately requires `current >= validFrom` and `validUntil >= current`.
Section 9.3.3 also requires RFC 5280 section 6.1 basic path validation. The
following links are a public mirror of the ISO PDF, not an ISO-hosted
publication: [ISO/IEC 18013-5:2021, page 59, section 9.3.1](https://iso.ieclist.ink/iec/ISO%20IEC%2018013-5-2021%20PDF.pdf#page=64)
and [page 60, section 9.3.3](https://iso.ieclist.ink/iec/ISO%20IEC%2018013-5-2021%20PDF.pdf#page=65).

The captured DS `notBefore` is 55 minutes after the MSO `signed` date. That
directly violates the section 9.3.1 `signed`-within-certificate-validity
requirement; this is not merely an implementation-policy disagreement.

The Suite labels DS path validation as the same ISO section 9.3.1 requirement in
[`ValidateMdocCredential.java`](https://gitlab.com/openid/conformance-suite/-/blob/c902d643e61dbb21f107d0e8eacdd8fb25fa2fed/src/main/java/net/openid/conformance/sequence/client/ValidateMdocCredential.java#L74)
(lines 74-84). Its helper calls `leafCert.checkValidity()` before PKIX
validation in
[`X509CertificateUtil.java`](https://gitlab.com/openid/conformance-suite/-/blob/c902d643e61dbb21f107d0e8eacdd8fb25fa2fed/src/main/java/net/openid/conformance/util/X509CertificateUtil.java#L105)
(lines 105-164), which evaluates at the helper's current time.

NazoAuth deliberately evaluates the leaf, intermediates, and anchor at MSO
`validityInfo.signed`: see local source
`D:\\self\\NazoAuth\\crates\\authorization-server\\src\\domain\\openid4vc\\credential_crypto\\mdoc.rs`,
lines 288-300 and 337-372. That is the behavior exercised by the sample, so
the leaf check implements the ISO `signed`-time requirement. NazoAuth also
evaluates intermediates and the anchor at that timestamp. ISO's quoted sentence
specifically names the MSO-header certificate, so this evidence establishes the
leaf violation; it does not independently prove that ISO requires the same
historical-time rule for every intermediate or anchor. That distinction is not
material for this capture because the IACA was valid at the MSO signed time.

The open-source OpenWallet Foundation Axle verifier independently implements
the same ISO step by carrying the DS `notBefore`/`notAfter` and checking MSO
`signed`; it documents this as separate from chain validation at the verifier's
clock. See its [spec matrix](https://github.com/openwallet-foundation-labs/axle/blob/main/SPEC-MATRIX.md).
Removing issuer validation would turn this standards violation into an
acceptance path and is not the remediation proposed here.

## Smallest upstream change proposal

No upstream source was modified. A standalone proposed patch is retained at
`%TEMP%\\nazoauth-oidf-warning-20260904\\upstream-mdoc-ds-validity.patch`.

It changes only the runtime test DS `notBefore` skew from five minutes to one
hour, with a comment tying it to the existing mdoc emission behavior. The DS
is minted before `TestAppUtils` provisions the MSO; therefore a one-hour
backdate puts `notBefore` no later than the subsequent `now - 1 hour` MSO
timestamp. It also covers VCI's floor-to-hour timestamp: for a mint at `t`,
the next VCI timestamp is at least `floor(t to hour)`, which is later than
`t - 1 hour`. The checked IACA is already valid from `2026-08-03T16:12:01Z`
through `2027-08-03T16:12:01Z`, so it covers the captured MSO time. This
preserves the Suite's existing one-hour `signedAt`/`validFrom` behavior.

Before an upstream submission, the maintainers should add a regression test
that validates the DS path at the earliest `signedAt` the corresponding helper
can generate. No Suite build or test was run for this diagnosis.

## Local verification commands

These commands use only private files already placed in the temporary evidence
directory. They do not require or print an authorization token.

```powershell
$evidence = Join-Path $env:TEMP 'nazoauth-oidf-warning-20260904'
openssl x509 -inform DER -in "$evidence\\suite-signer.der" -noout -dates -fingerprint -sha256
openssl verify -CAfile "$evidence\\matrix-iaca.pem" -attime 1788492561 "$evidence\\suite-signer.pem"
openssl verify -CAfile "$evidence\\matrix-iaca.pem" -attime 1788496161 "$evidence\\suite-signer.pem"
```
