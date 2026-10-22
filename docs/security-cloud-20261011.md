# Security Cloud verification — 2026-10-11

Source baseline: `e2525b4bd7b6a9fbaca4cade6798be264c924562`. Verification covers code changes and regression tests at the commit containing this report.

## Results

26 findings are fixed (25 repaired here; the ChromeDriver listener was already removed). The former `proxy_tls` capability finding is not reproduced under the current host-owner model and is not marked fixed through the Security Cloud API, which has no dismissal operation.

The repairs preserve the existing host/controller boundary: credentials leave argv; libpq TLS policy survives maintenance connections; default curl configuration and attacker PATH cannot influence privileged helpers; mutable filesystem traversal uses no-follow descriptors; OCI reuse and replacement verify ownership, stopped state and immutable identity; local cleanup precedes Suite availability; CIBA binds the run client; VP-only mdoc material keeps its certificate profile; stopped deployments retain their port reservation.

| Finding | Result |
| --- | --- |
| `commit:05ac5c5c81fc819186f969b1bf0e5078` — OIDF bearer token is exposed through the process command line | Fixed in this revision |
| `commit:3c18952b466c8191b79ab30f73331d0a` — Clean installs trust spoofable Client-Cert headers | Fixed in this revision |
| `commit:6b86f67333ec8191984cc39f839aff4b` — Control operations expose DB URL in process arguments | Fixed in this revision |
| `commit:dae4d1a7ecf881919cc525fb6b8f843b` — Database URLs leaked through one-shot command argv | Fixed in this revision |
| `commit:f12777eed0b881918aebdbc5ce03cfe2` — createdb/dropdb discard PostgreSQL TLS policy | Fixed in this revision |
| `commit:310fcea601908191b576a1c75f4152c1` — Installer can run a post-attestation TMPDIR swap | Fixed in this revision |
| `commit:15ecfc2ce0ac819199b90a94b7cd4788` — Managed ChromeDriver exposes unauthenticated local WebDriver | Fixed before this revision |
| `commit:6dfaec8ce95c8191aa9860b8bf8f096a` — Proxy reload executable is validated by path only | Fixed in this revision |
| `commit:9711c8d7ef0481919b299ecc879158f8` — Suite test names can amplify progress logs into disk exhaustion | Fixed in this revision |
| `commit:e4c6936f5a408191841ae335fb7e4c18` — OIDF generator no longer pins source matrix bytes | Fixed in this revision |
| `commit:89cd92aa5bfc8191a0d5fbd2f1f7e61a` — Uninstall symlink race lets service users chmod host files as root | Fixed in this revision |
| `commit:6cf1d2a4935081919bd6246f6afc2fce` — Inherited HOME lets curl read attacker .curlrc as root | Fixed in this revision |
| `commit:1d76b2c1a0cc819192f6e3aefe74e792` — Canonicalized temp dirs can be raced into deleting host paths | Fixed in this revision |
| `commit:4d68bbb274748191bf4005239b676bdf` — Operator-state chown has symlink race | Fixed in this revision |
| `commit:a73a6903027481918c58d5e18eec5f0d` — Suite cleanup failure blocks tenant resource recovery | Fixed in this revision |
| `commit:0adcb356869c819187c5e62b0dcac654` — CIBA callback not bound to signed clients | Fixed in this revision |
| `commit:d60173b1e4f08191aa75ce6404483225` — Interactive Suite token prompt echoes the bearer token | Fixed in this revision |
| `commit:866a6e2c9b048191b1896f3f59f8af69` — VP-only mdoc runs omit the required mdoc certificate profile | Fixed in this revision |
| `commit:94ed54f04a608191aa9dbd9d22cfca2a` — Unconditional container rm breaks fresh replacements | Fixed in this revision |
| `commit:eadd0b83bd24819189733833a50581dc` — Failing one-shot stderr can leak lifecycle credentials | Fixed in this revision |
| `commit:afdef30c3e5881919002625d41a58fa8` — Restore rehearsal can expose lifecycle database credentials | Fixed in this revision |
| `commit:9026b6846ec881918805e934d846758b` — Strict exit checks discard durable OCI task receipts | Fixed in this revision |
| `commit:3029908a4bb88191b7625986b10a4d4f` — Install can start an unowned container based only on its digest | Fixed in this revision |
| `commit:e2fe2e0b0de081919c699fbf2354e86f` — Stopped deployments can lose their assigned loopback port | Fixed in this revision |
| `commit:ecc7c3cc92e08191b547886019ce4fd1` — Windows USERPROFILE inheritance enables curl config injection | Fixed in this revision |
| `commit:f909bc6106f88191967c8ccb02ebc211` — Privileged helpers execute through attacker-controlled PATH | Fixed in this revision |
| `commit:6ef83f4a315081918a8b8e2c2ed5ca60` — TLS mutations no longer require proxy_tls capability | Not reproduced; keep open for review |

## Verification

| Actual command | Exit | Evidence |
| --- | --- | --- |
| `cargo +1.97.1 test --workspace --locked --no-fail-fast` (`RUST_TEST_THREADS=1`, `LC_ALL=C`) | 0 | Full final workspace suite, including the new unsafe-parent and recovery-secret cases |
| `cargo +1.97.1 clippy --workspace --all-targets --locked -- -D warnings` | 0 | Final all-target Clippy |
| `cargo +1.97.1 fmt --all --check` | 0 | Final formatting |
| `python3 scripts/oidf/test_generate_oidf_artifact.py` | 0 | Real Git replace-object regression; producer reads original signed source bytes |
| `bash -n scripts/install_nazoauthctl.sh` | 0 | Installer syntax |

The pre-repair regression run compiled and exited 101: argv token acceptance, lost libpq connection policy, curl config injection and stderr disclosure assertions failed. The same four tests passed after repair (exit 0). Additional real subprocess fixtures verified secret-free OCI argv with environment delivery and structured nonzero operator receipts. The installer regression used a fake attestation executor and an isolated install root: baseline staging followed attacker `TMPDIR`; repaired staging stayed below the protected install parent. It did not install or upgrade a system binary.

Full suites also cover descriptor traversal refusing symlinks and hard links, client-bound CIBA callbacks, materialized VP-only mdoc country and critical EKU, unowned/running container replacement rejection, matching install ownership/mounts/environment, default forwarded-certificate trust disabled, and persistent port conflict rejection. Host root and the container engine remain trusted administrators with access to process secrets. The shared curl argument rule was tested on Linux; native Windows execution remained untested in this report.

## Findings that must not be blindly restored

`commit:6ef83f4a315081918a8b8e2c2ed5ca60`: the retired capability-grant model is no longer the authorization source. Current TLS apply loads a protected provider, checks tenant/hostname binding, serializes deployment and provider mutation, and binds existing receipts to provider authority. An ordinary tenant has no controller filesystem or privileged local command access. The report assumes a separately delegated low-privilege automation boundary that this CLI does not expose. Do not restore a parallel permission registry solely to satisfy that obsolete premise. A deployment that externally delegates this CLI must restrict that delegation itself.

## Delivery boundary

Delivery consisted of source changes and the regression checks above. OIDF and
mdoc privacy results are recorded in their dated reports. Security Cloud closure
references this source commit and the tests above.
