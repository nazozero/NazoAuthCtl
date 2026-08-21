# Local OCI candidate installation

`nazoauthctl install` can create a new, declaration-bound standards-full
deployment from an OCI image which is already present in Podman or Docker.
This path exists for an isolated conformance candidate; it is neither an
unsigned `update` nor an adoption of an arbitrary running container.

It is fresh-only. An existing controller config is never converted into this
mode. A retry requires incomplete local-candidate state and the exact original
arguments. It normally has no registered binding; the only exception is the
narrow crash window after this exact candidate declaration/registry binding
was durably written but before candidate completion. That retry proves the
same record first and only completes its recovery evidence—it does not replay
application tasks. A signed, adopted, development, or any other registered
deployment is rejected before candidate work begins.

Use all five candidate options together:

```text
--candidate-image IMAGE
--candidate-release vVERSION
--candidate-revision FULL_LOWERCASE_GIT_SHA
--candidate-build-id source:FULL_LOWERCASE_GIT_SHA
--candidate-oci-digest sha256:LOWERCASE_MANIFEST_DIGEST
```

The candidate path rejects `--to`, the host runtime, and
`--external-dependencies`. It requires the `standards-full` profile and uses
the ordinary Ctl-managed PostgreSQL, Valkey, generated secret material, and
managed backup flow. It therefore requires a fresh deployment root and does
not adopt, share, or infer credentials for hand-created dependency containers.
It is an HTTPS trusted-proxy contract: Ctl requires a paired single-host
`--trusted-proxy-cidr` and writes `TRANSPORT_MODE: "trusted-proxy"` together
with `TRUSTED_PROXY_CIDRS` and `MTLS_CERTIFICATE_SOURCE: "rfc9440"`.
NazoAuth defaults `CLIENT_IP_HEADER_MODE` to `none`; Ctl does not select a
forwarded-client-IP header policy implicitly.

`--profile-material` is strict, non-secret JSON and is validated before Ctl
creates any config, controller identity, or managed object. Its required
top-level fields are `credential_configurations`,
`wallet_authorization_origins`, `ciba_notification_private_origins`, and
`backchannel_logout_private_origins`; client/key-attestation material is
optional. Every credential configuration accepts only the NazoAuth 45959681
schema: `format` is `dc+sd-jwt` or `mso_mdoc`,
`credential_signing_alg_values_supported` is exactly `["ES256"]`, and the
optional binding/proof declarations obey NazoAuth's `jwk` plus
`jwt`/`attestation` rules. For example:

```json
{
  "credential_configurations": {
    "example": {
      "format": "dc+sd-jwt",
      "scope": "example",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
      },
      "vct": "https://issuer.example/credentials/example"
    }
  },
  "wallet_authorization_origins": ["https://suite.example"],
  "ciba_notification_private_origins": ["https://suite.example"],
  "backchannel_logout_private_origins": ["https://suite.example"]
}
```

Ctl writes this as the single quoted JSON string in
`OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON`; it does not treat the YAML value
as a nested object. Optional client-attestation JWKS may contain only unique,
non-empty `kid` EC P-256 public keys with string `x`/`y`; optional holder-key
attestation JWKS additionally permits OKP Ed25519 with string `x`. Imported
VCI and VP management tokens must be distinct.

Before a migration, key task, or runtime replacement,
the controller resolves the supplied image only from the selected local runtime,
then proves its immutable local image ID, OCI manifest digest, and embedded
release/revision/build ID against the supplied bindings. It never invokes an
image pull on this path.

The exact candidate binding is first persisted as a config sibling intent,
before the fresh controller config is published; the intent can restore that
config after an interruption only for the same five inputs. The immutable local
image ID is then persisted before privileged work. A retry must repeat all five
inputs and resolve the same local object.
The resulting DeploymentRecord binds the controller config, runtime ownership,
local image ID, expected OCI digest, and the complete embedded identity, so an
ordinary conformance session rechecks all of them before tenant-resource work.

Before registration and on an exact completed-install retry, Ctl also checks
the public HTTPS `/.well-known/nazoauth-control` endpoint. It sends a fresh
nonce and accepts at most 64 KiB; the returned JWS must verify under the
descriptor-bound `identity.pub` mounted for this runtime. Its deployment ID,
runtime ID, issuer, release, revision, build ID, protocol versions, and key ID
must exactly match the local descriptor and candidate binding. An unavailable,
expired, wrong-key, wrong-nonce, or mismatched public statement leaves the
install pending and does not register a completed deployment.

Once completed, this deployment is permanently frozen as that exact candidate.
`update --yes`, development activation, migrations, and capability/provenance
transitions cannot replace its active release or runtime. Conformance and
read-only status/doctor diagnostics remain available. Promotion to a signed
Release is intentionally not implicit and requires a future explicit promotion
transaction.

The digest is the local OCI manifest digest reported by the chosen runtime, not
a mutable image tag and not the local image ID. Retagging `IMAGE` therefore
cannot change a resumed candidate: the stored local image ID, the reported
manifest digest, and the embedded identity must all still match.

This is an isolated candidate preflight boundary, not a recovery contract.
Its record remains `RequiresUserEvidence`: Ctl does not claim automated
rollback, registered recovery, or clean-machine reconstruction. Pending state
blocks conformance, update, development activation, and other controller
mutations. Once completed, `recover`, `rollback`, `update`, development
activation, adoption, and migration remain fail-closed; only conformance and
read-only diagnostics are available. `status` and `doctor` retain evidence for
an explicit operator decision rather than silently restoring or replacing the
candidate.
