//! Temporary, explicit upstream incompatibilities. Never rewrite Suite results.

use std::collections::BTreeMap;

// TODO: remove this exclusion when the selected Suite's CIBA positive/control
// flows use issuer-only client assertion audiences at both authenticated endpoints,
// and rerun these modules against the unchanged RFC 10070 server policy.
// Tracked by https://gitlab.com/openid/conformance-suite/-/issues/1499.
// Reviewed release-v5.3.3, release-v5.3.4 and master daca6ad2068468d42557ea1152f899cc3ac01a10.
// Exact names keep discovery, mTLS, other profiles and unknown future tests running.
const CIBA_ENDPOINT_AUDIENCE_MODULES: &[&str] = &[
    "fapi-ciba-id1",
    "fapi-ciba-id1-user-rejects-authentication",
    "fapi-ciba-id1-multiple-call-to-token-endpoint",
    "fapi-ciba-id1-auth-req-id-expired",
    "fapi-ciba-id1-ensure-authorization-request-with-binding-message-succeeds",
    "fapi-ciba-id1-ensure-other-scope-order-succeeds",
    "fapi-ciba-id1-ensure-requested-expiry-as-string-succeeds",
    "fapi-ciba-id1-ensure-authorization-request-with-potentially-bad-binding-message",
    "fapi-ciba-id1-ensure-request-object-missing-aud-fails",
    "fapi-ciba-id1-ensure-request-object-bad-aud-fails",
    "fapi-ciba-id1-ensure-request-object-missing-iss-fails",
    "fapi-ciba-id1-ensure-request-object-bad-iss-fails",
    "fapi-ciba-id1-ensure-request-object-missing-exp-fails",
    "fapi-ciba-id1-ensure-request-object-expired-exp-fails",
    "fapi-ciba-id1-ensure-request-object-exp-is-70-minutes-in-future-fails",
    "fapi-ciba-id1-ensure-request-object-missing-iat-fails",
    "fapi-ciba-id1-ensure-request-object-missing-nbf-fails",
    "fapi-ciba-id1-ensure-request-object-nbf-is-10-minutes-in-future-fails",
    "fapi-ciba-id1-ensure-request-object-nbf-is-70-minutes-in-past-fails",
    "fapi-ciba-id1-ensure-request-object-missing-jti-fails",
    "fapi-ciba-id1-ensure-request-object-signature-algorithm-is-none-fails",
    "fapi-ciba-id1-ensure-request-object-signature-algorithm-is-bad-fails",
    "fapi-ciba-id1-ensure-request-object-signature-algorithm-is-RS256-fails",
    "fapi-ciba-id1-ensure-request-object-signed-by-other-client-fails",
    "fapi-ciba-id1-ensure-authorization-request-with-multiple-hints-fails",
    "fapi-ciba-id1-ensure-wrong-auth-req-id-in-token-endpoint-request",
    "fapi-ciba-id1-ensure-without-client-assertion-in-token-endpoint-request",
    "fapi-ciba-id1-ensure-invalid-client-assertions-in-backchannel-authorization-request-fail",
    "fapi-ciba-id1-ensure-client-assertion-signature-algorithm-in-token-endpoint-request-is-RS256-fails",
    "fapi-ciba-id1-ensure-client-assertion-with-iss-aud-to-token-endpoint-succeeds",
    "fapi-ciba-id1-ping-backchannel-notification-endpoint-response-has-body",
    "fapi-ciba-id1-ping-backchannel-notification-endpoint-response-401",
    "fapi-ciba-id1-ping-backchannel-notification-endpoint-response-403",
    "fapi-ciba-id1-ping-with-mtls-ciba-notification-endpoint-response-401-and-require-server-does-not-retry",
    "fapi-ciba-id1-ping-backchannel-notification-endpoint-return-redirect-request",
    "fapi-ciba-id1-ensure-unsigned-backchannel-authorization-request-fails",
    "fapi-ciba-id1-refresh-token",
    "fapi-ciba-id1-ensure-mtls-holder-of-key-required",
    "fapi-ciba-id1-ensure-mtls-holder-of-key-required-at-non-alias-token-endpoint",
];

pub(crate) fn temporary_exclusion(
    plan_name: &str,
    test_name: &str,
    variant: &BTreeMap<String, String>,
) -> Option<&'static str> {
    // TODO: restore this exact mTLS module when the Suite accepts the OAuth
    // 400 invalid_client response for authentication without an HTTP challenge.
    // CIBA's open erratum does not justify inventing a Basic challenge for mTLS.
    if plan_name == "fapi-ciba-id1-test-plan"
        && test_name
            == "fapi-ciba-id1-ensure-different-client-id-and-issuer-in-backchannel-authorization-request"
        && variant.get("client_auth_type").map(String::as_str) == Some("mtls")
        && variant.get("fapi_ciba_profile").map(String::as_str) == Some("plain_fapi")
        && matches!(
            variant.get("ciba_mode").map(String::as_str),
            Some("poll" | "ping")
        )
    {
        return Some(
            "Suite requires HTTP 401 for mTLS invalid_client, which has no applicable HTTP challenge; not executed pending https://github.com/openid/modrna/issues/213 and the Suite correction.",
        );
    }
    (plan_name == "fapi-ciba-id1-test-plan"
        && variant.get("client_auth_type").map(String::as_str) == Some("private_key_jwt")
        && variant.get("fapi_ciba_profile").map(String::as_str) == Some("plain_fapi")
        && matches!(variant.get("ciba_mode").map(String::as_str), Some("poll" | "ping"))
        && CIBA_ENDPOINT_AUDIENCE_MODULES.contains(&test_name))
    .then_some(
        "RFC 10070 section 4: Suite CIBA sends endpoint audiences; not executed pending issuer-only upstream flows. https://gitlab.com/openid/conformance-suite/-/issues/1499",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtls_challenge_exclusion_is_limited_to_confirmed_variants() {
        let plan = "fapi-ciba-id1-test-plan";
        let test = "fapi-ciba-id1-ensure-different-client-id-and-issuer-in-backchannel-authorization-request";
        for mode in ["poll", "ping"] {
            let variant = BTreeMap::from([
                ("client_auth_type".into(), "mtls".into()),
                ("fapi_ciba_profile".into(), "plain_fapi".into()),
                ("ciba_mode".into(), mode.into()),
            ]);
            assert!(temporary_exclusion(plan, test, &variant).is_some());
            assert!(temporary_exclusion("another-plan", test, &variant).is_none());
            assert!(temporary_exclusion(plan, "fapi-ciba-id1", &variant).is_none());
            for (key, value) in [
                ("client_auth_type", "private_key_jwt"),
                ("fapi_ciba_profile", "other"),
                ("ciba_mode", "push"),
            ] {
                let mut other = variant.clone();
                other.insert(key.into(), value.into());
                assert!(temporary_exclusion(plan, test, &other).is_none());
                other.remove(key);
                assert!(temporary_exclusion(plan, test, &other).is_none());
            }
        }
    }
}
