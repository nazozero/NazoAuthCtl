# OIDC RP black-box setup

NazoAuth is the **system under test**. NazoAuthCtl drives the official OIDF
Suite as upstream OpenID Provider, using real HTTPS and the released NazoAuth
binary. It never constructs in-process Federation services or writes a test
identity link directly into PostgreSQL.

## Prepare the independent production instance

Before running RP cases, provision a disposable, independently deployed
NazoAuth instance through its normal lifecycle. Its startup
`FEDERATION_PROVIDER_CONFIGS` must include four **enabled OIDC providers**.
All four share the Suite static client ID/secret, but have distinct provider
IDs and registered HTTPS callback URLs:

- Basic: static authorization/token/JWKS endpoints to the Suite issuer
- Configuration: issuer Discovery enabled
- Configuration JWKS: Discovery enabled, scope `openid` only
- Back-Channel Logout: Discovery, Back-Channel Logout and RP-initiated logout

The three Suite aliases are fixed for the run and must match the OIDC issuers
configured on the production instance. Each callback is the normal
`https://RP_ORIGIN/auth/federation/PROVIDER_ID/callback`. The logout return
URI must be a normal same-origin application URL, not a test-only endpoint.

Store the following operator-provided JSON in an owner-private file.
The configured client secret must match the real Suite static client.

```json
{
  "schema": 1,
  "client_id": "rp-client",
  "client_secret": "private-generated-client-secret",
  "basic": {"alias": "rp-basic-owned-alias", "provider_id": "rp-basic"},
  "configuration": {"alias": "rp-config-owned-alias", "provider_id": "rp-config"},
  "configuration_keys_provider_id": "rp-config-keys",
  "backchannel": {"alias": "rp-logout-owned-alias", "provider_id": "rp-logout"},
  "post_logout_redirect_uri": "https://rp.example/ui/login",
  "session_cookie_name": "nazo_session",
  "csrf_cookie_name": "nazo_csrf"
}
```

The target origin and immutable binary identity are taken from the
controller's verified `--instance` deployment. The Suite URL and API
credentials are managed by the existing `oidf configure` workflow.

```sh
nazoauthctl --instance rp-test oidf run oidc-rp --rp-config /private/rp.json --json
nazoauthctl --instance rp-test oidf run oidc --rp-config /private/rp.json --json
```

Without `--rp-config`, `oidf run` retains its existing 44 OP/AS plans and
`oidf run oidc` retains its nine OP plans. Neither implies RP coverage.

## Evidence and acceptance

The RP lane creates official Basic, Configuration and Back-Channel plans
using the existing Suite API. Module results are preserved in their original
PASSED, FAILED or SKIPPED categories. Each raw Suite module log is saved in
the existing private run-evidence directory, alongside the RP report.
The controller also asserts the local callback's session and CSRF behavior
and uses the normal `/auth/me` route to verify session revocation.

**Known black-box precondition:** a first federated login can provision an
account only when the upstream returns a verified email. The current public
federation-link endpoints support listing/unlinking but not user-initiated
linking. Some Suite RP cases have no verified email. For such cases an
ordinary prior account/link establishment must be demonstrated; the
old in-process RP fixture's direct identity-link insertion is forbidden.
If no legitimate production path exists, that case is reported incomplete
rather than accepted as successful, and issue #101 remains open.

The new lane's presence does not itself establish official OIDF certification
or prove a successful external end-to-end run. These require actual
deployment, Suite execution and inspectable evidence.
