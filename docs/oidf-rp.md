# OIDC RP black-box setup

NazoAuth is the **system under test**. NazoAuthCtl drives the official OIDF
Suite as upstream OpenID Provider, using real HTTPS and a production NazoAuth
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
  "post_logout_redirect_uri": "https://rp.example/live",
  "session_cookie_name": "nazo_session",
  "csrf_cookie_name": "nazo_csrf",
  "account": {"email": "rp-acceptance@example.com", "password": "private-account-password"}
}
```

Use a dedicated disposable local account with a password and no MFA, created
through normal registration or administrator provisioning. During a run, that
account and these four providers are exclusive to this controller. The driver
records its existing links before making changes and removes only links it
created in the four configured provider scopes. Keep this file owner-private;
account passwords and Suite client secrets are never written to the recovery
journal or public report.

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

Before the 28 conformance modules run, the controller signs in to the local
fixture account and starts each binding through
`POST /auth/me/federation/links/{provider_id}/start`. The ordinary callback
verifies the original Suite OP response and binds its subject to that same
account. Setup modules and their original Suite states are recorded separately.
The conformance modules then start with a fresh browser cookie jar and must
establish a real local session for that account. Invalid identity callbacks must
return 401 without a local session; an issuer mismatch in Discovery must reject
the metadata before authorization starts. Key rotation performs both required
logins.

Every Suite plan and module has a durable create intent before the API request.
Its returned opaque ID replaces that intent. A later run recovers an interrupted
run through the existing Suite cleanup API and the ordinary account unlink
endpoint. An unknown create response stays pending for operator reconciliation;
resources are never guessed from aliases. Completed runs retain an ownership
receipt alongside their incrementally saved report, including failed assertions.

CI runs the same controller driver against an independent production NazoAuth
binary, provisioned with the normal `migrate` and `admin-provision` commands.
It uses the unmodified, digest-pinned original OIDF Suite. Evidence records both
source commits, the binary SHA-256, the live Suite version and the original
module outcomes. Private raw logs are exported with fixture secrets redacted;
PASSED, FAILED, REVIEW and SKIPPED results remain unchanged. The two unsigned
ID Token cases retain their Suite SKIPPED result.
