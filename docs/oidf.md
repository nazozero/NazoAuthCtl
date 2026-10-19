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
NazoAuth-owned default. The first run command runs the complete Matrix bundled
in the signed NazoAuthCtl release. The second uses a stable group
alias; the third selects one exact bundled plan. The other aliases are
`oidc`, `fapi`, `openid4vci`, `openid4vp`, and `openid4vc`. Unknown selectors
fail and print the valid aliases, groups, and plans.

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
and image digest. The reference is release-v5.3.3; it describes the version
against which these inputs are checked, not an attestation of a remote server.
The actual configured Suite origin and its reported module outcomes are recorded
separately. Official, self-hosted and third-party Suite origins use the same path.

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
