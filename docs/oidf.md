# OIDF testing

Human output follows the CLI locale and uses readable fields. Place `--json`
before the command to obtain the complete structured result. See
[language and presentation](cli-presentation.md).

The normal user workflow has no artifact configuration:

```text
nazoauthctl oidf configure --tenant-domain oidf.example.com --suite https://suite.example
nazoauthctl oidf run
nazoauthctl oidf run ciba
nazoauthctl oidf run oidc-core-p001
```

The configuration command stores the operator-owned wildcard DNS suffix and
the selected Suite origin once for the selected instance. Neither has a
NazoAuth-owned default. The first run command selects the complete Matrix bundled
in the signed NazoAuthCtl release, with the explicit temporary exclusions below.
The second uses a stable group
alias; the third selects one exact bundled plan. The other aliases are
`oidc`, `fapi`, `openid4vci`, `openid4vp`, and `openid4vc`. `oidc` selects
the nine existing **OpenID Provider** plans across Core, Logout and Session
Management (the `oidc-core`, `oidc-logout`, and `oidc-session` groups).
The selector previously covered only Core. Unknown selectors fail and print the
valid aliases, groups, and plans.

### RP is a separate test role

NazoAuth also acts as an OIDC Relying Party for upstream federation. The OIDF
**RP** Basic, Configuration and Back-Channel Logout plans exercise the opposite
direction: the Suite is the upstream OP and NazoAuth is the client. They run
against NazoAuth's production Native RP handlers in
[`OIDC RP research`](https://github.com/nazozero/NazoAuth/actions/workflows/oidc-rp-research.yml),
not through `nazoauthctl oidf run`. The [RP changes and evidence](https://github.com/nazozero/NazoAuth/pull/299)
record which official modules ran and the two unsigned-ID-Token modules that
the Suite skipped. These are conformance test results, not a claim of RP
certification.

The controller's existing OIDF tenant-resource flow cannot configure a new
upstream RP provider or bind a Suite test identity into the deployed server.
Adding the three RP plan names to this OP Matrix would start the wrong
direction of the protocol and misreport incomplete work as RP coverage.
Keep RP evidence in the server's existing CI until a real production-facing
RP fixture and controller driver are available; do not add test-only provider
management to the server.

NazoAuthCtl automatically creates a temporary tenant below the configured domain,
fresh test material, managed browser workers, and a private evidence directory.
For CIBA, ctl reads the authenticated Suite log and completes the requested
allow or deny action through the same login and CIBA decision endpoints used by
an ordinary tenant user. NazoAuth exposes no conformance-only route. On the
first interactive run ctl securely
prompts for the selected Suite API token and stores it in the platform
credential store. Non-interactive jobs may pipe the token with
`--token-stdin`. Tokens are never accepted as command-line values, and the
interactive prompt hides input. Recovery of local tenant and proxy resources
runs before Suite authentication; Suite cleanup remains journaled for a later
retry when the remote Suite is unavailable.

Ordinary Suite module failures are collected while later selected work continues
by default; the final run still fails when any module failed. `--fail-fast`
stops later dispatch after the first ordinary failure. Interrupts, ctl
automation failures, unresolved resource ownership, and cleanup-safety
conditions stop the run regardless of that option. Started Suite plans are
retained and their exact IDs and Suite origin are printed so the operator can
inspect the same records in the Suite UI; plans that never started are deleted.
A CIBA test that explicitly requires uploaded visual evidence is likewise
retained as review pending instead of being reported as an automated pass.

## Test inputs and evidence

The Matrix and driver are embedded in the controller release. There is no
separate artifact publisher, signing key, trust policy, download cache or
`oidf artifact` command. The controller compiles the selected bundled plans
directly; group selection, exclusions and bounded execution remain supported.

Evidence schema 5 records the controller version, Matrix and driver digests,
the combined input identity, and the reference Suite release, source revision
and image digest. The OP/AS Matrix reference remains release-v5.3.3, the version against which
these particular bundled inputs were checked. NazoAuth's independent RP workflow
uses its own pinned Suite release-v5.3.4. Changing the controller's reference
requires verification of its 44 OP/AS plans against that Suite, not merely
copying the newer reference from the RP workflow.
The actual configured Suite origin and its reported module outcomes are recorded
separately. Official, self-hosted and third-party Suite origins use the same path.

Suite compatibility follows the protocol implementation, not the reverse. The
controller owns test registrations, user interaction and evidence collection;
NazoAuth owns ordinary protocol and management endpoints. A Suite incompatibility
must not enable a server exception or change an official outcome.

The upstream [release-v5.3.4 source](https://github.com/openid-certification/conformance-suite/tree/23353b36957d6466010de767c812d2c91ed37638)
adds VP credential-type and revocation tests, VCI client-attestation negative
tests, and CIBA ping concurrency fixes. Its generic VCI/VP Final plans are marked
alpha and non-certifiable; the corresponding HAIP plans are certifiable. Those
labels describe the plans, not certification of NazoAuth.
FAPI 2 Final and its VCI issuer subclass generate issuer-audience assertions.
CIBA still generates endpoint-audience assertions in normal private-key flows,
including in [upstream revision daca6ad](https://github.com/openid-certification/conformance-suite/blob/daca6ad2068468d42557ea1152f899cc3ac01a10/src/main/java/net/openid/conformance/sequence/client/AddPrivateKeyJWTClientAuthenticationToBackchannelRequest.java).
This conflicts with [RFC 10070 section 4](https://www.rfc-editor.org/rfc/rfc10070.html#section-4).
The existing upstream [issue #1499](https://gitlab.com/openid/conformance-suite/-/issues/1499)
tracks tests that fail against issuer-only client authentication.

Until upstream fixes these flows, ctl does not instantiate the exact known
CIBA `private_key_jwt` modules listed in `suite_compatibility.rs`, for the bundled
`plain_fapi` ping/poll variants. Discovery, other mTLS modules, other plans and unknown
new modules still run. All 44 OP/AS plans remain in the Matrix. The controller neither
changes assertions nor enables a server exception.

The exact mTLS module
`fapi-ciba-id1-ensure-different-client-id-and-issuer-in-backchannel-authorization-request`
is also temporarily excluded for `plain_fapi` ping/poll. It requires HTTP 401
for authentication that has no applicable HTTP challenge, whereas NazoAuth
returns OAuth `400 invalid_client`. [CIBA issue #213](https://github.com/openid/modrna/issues/213)
tracks the specification conflict. Restore this module when the Suite accepts
that response and rerun it against unchanged server policy. Other mTLS tests
remain enabled.

Each plan's `temporary_exclusions` records the unexecuted module name, effective
variant and reason with the upstream issue. `defined_modules` on the plan still
counts the complete Suite definition; execution/progress/integrity counts cover
the selected subset. These exclusions are not official Suite `SKIPPED` results
and never count as passes. `suite_pass` stays false while exclusions exist;
`acceptance_pass` and the CLI exit status evaluate the executed subset and normal
cleanup, with the partial scope printed explicitly. Remaining failures still fail
the run. JSON and private evidence retain the complete exclusion inventory.

Remove the temporary list after upstream's positive/control flows use issuer-only
assertion audiences at both the backchannel and token endpoints and those modules
have been rerun against the unchanged server policy. Source review and controller
regressions alone do not qualify a new reference image or prove a full Suite run.

Recovery journals retain their persisted content identities and resource
ownership records. Upgrading the controller does not recompute old run identities
or require the old Matrix to clean up temporary tenants, proxy trust or Suite
resources. Suite retention records and review evidence remain available.

The run evidence sink commits each run into a unique owner-only directory with
a manifest-last digest envelope, and preserves structured output when outer
cleanup fails. Control evidence binds every operation to its operation ID,
canonical request hash, typed result, revision, and manifest transition, and
proves cleanup back to the enumerated baseline. Suite outcomes and controller
evidence remain distinct facts; neither is presented as a Suite signature.

Before ordinary Apply, `oidf run` durably stores the exact
`ControlOperation`, canonical request hash, and private manifest path. Response
loss replays that same operation. Cleanup first enumerates the run identities,
then issues a digest-bound Revoke, persists each typed terminal result, and
removes the private manifest only through the journal's deletion-intent state
machine. mTLS trust is an ordinary tenant resource; ingress forwards the RFC
9440 client-certificate header and no per-run proxy trust file is installed.

The pinned operator-protocol dependency remains authoritative for its exported
types. The existing VP receipt/intent extension in `oidf_protocol.rs` is not
present in that pinned revision. Its active consumers remain explicit local
imports until the producer and shared protocol can be updated together; it must
not masquerade as a re-export of the dependency. Removing it independently
would remove a currently used conformance capability.

A terminal failed tenant Disable or Finalize settles that control operation. The
next cleanup attempt reads the current directory revision and creates a new
operation, so a concurrent directory update cannot pin recovery to a stale CAS.
An in-progress result or lost response keeps the original operation and revision
until its durable outcome is known. The revision is cleared only after the
controller operation journal has settled the terminal result.
