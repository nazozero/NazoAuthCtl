#!/usr/bin/env python3
"""Provision an isolated ordinary NazoAuth process through its production CLI."""

import argparse
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import uuid


def private_json(path, value):
    with open(path, "x", opener=lambda name, flags: os.open(name, flags, 0o600)) as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    directory = args.directory.resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    suite = "https://localhost:8443"
    origin = "https://localhost:8445"
    account = {"email": "rp-acceptance@example.com", "password": secrets.token_urlsafe(36)}
    client_id = "nazoauth-rp-acceptance"
    client_secret = secrets.token_urlsafe(32)
    deployment = "rp-" + uuid.uuid4().hex
    providers = []
    for provider_id, alias, discovery, logout, scope in [
        ("rp-basic", "rp-basic", False, False, "openid email profile"),
        ("rp-config", "rp-config", True, False, "openid email profile"),
        ("rp-config-keys", "rp-config", True, False, "openid"),
        ("rp-logout", "rp-logout", True, True, "openid email profile"),
    ]:
        issuer = suite + "/test/a/" + alias + "/"
        provider = {
            "provider_id": provider_id, "enabled": True,
            "display_name": provider_id, "adapter_type": "oidc",
            "issuer": issuer, "discovery": discovery, "backchannel_logout": logout,
            "client_id": client_id, "client_secret": client_secret,
            "redirect_uri": origin + "/auth/federation/" + provider_id + "/callback",
            "scopes": scope,
        }
        if not discovery:
            provider.update({"authorization_endpoint": issuer + "authorize",
                             "token_endpoint": issuer + "token",
                             "jwks_url": issuer + "jwks", "userinfo_endpoint": issuer + "userinfo"})
        if logout:
            provider["post_logout_redirect_uri"] = origin + "/live"
            provider["id_token_signed_response_alg"] = "RS256"
        providers.append(provider)
    config = {
        "BIND": "127.0.0.1:18080", "PUBLIC_BASE_URL": origin,
        "MTLS_ENDPOINT_BASE_URL": origin, "TRANSPORT_MODE": "trusted-proxy",
        "TRUSTED_PROXY_CIDRS": "127.0.0.1/32", "MTLS_CERTIFICATE_SOURCE": "disabled",
        "DATABASE_URL": os.environ["DATABASE_URL"], "VALKEY_URL": os.environ["VALKEY_URL"],
        "VALKEY_STATE_EPOCH": str(uuid.uuid4()), "DEPLOYMENT_ID": deployment,
        "COOKIE_SECURE": True, "SESSION_COOKIE_NAME": "nazo_session", "CSRF_COOKIE_NAME": "nazo_csrf",
        "FRONTEND_BASE_URL": origin, "CORS_ALLOWED_ORIGINS": origin,
        "FEDERATION_PROVIDER_CONFIGS": json.dumps(providers), "EMAIL_DELIVERY": "disabled",
        "DATA_DIR": str(directory / "runtime"), "UI_ENABLED": False,
        "SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE": False,
        "RUST_LOG": "info",
    }
    # Configuration is JSON, which is also a YAML document. The production
    # loader remains the single source of configuration and secret defaults.
    config_path = directory / ".env.yaml"
    private_json(config_path, config)
    credential_path = directory / "administrator.json"
    private_json(credential_path, {"schema": 1, **account})
    settings_path = directory / "rp-settings.json"
    private_json(settings_path, {
        "schema": 1, "client_id": client_id, "client_secret": client_secret,
        "account": account,
        "basic": {"alias": "rp-basic", "provider_id": "rp-basic"},
        "configuration": {"alias": "rp-config", "provider_id": "rp-config"},
        "configuration_keys_provider_id": "rp-config-keys",
        "backchannel": {"alias": "rp-logout", "provider_id": "rp-logout"},
        "post_logout_redirect_uri": origin + "/live",
        "session_cookie_name": "nazo_session", "csrf_cookie_name": "nazo_csrf",
    })
    env = dict(os.environ, NAZOAUTH_SERVER_CONFIG_FILE=str(config_path))
    log_path = directory / "server-private.log"
    with open(log_path, "x", opener=lambda name, flags: os.open(name, flags, 0o600)) as log:
        subprocess.run([str(binary), "migrate"], cwd=directory, env=env, check=True, stdout=log, stderr=log)
        provision_env = dict(env, NAZOAUTH_ADMIN_PROVISION_FILE=str(credential_path),
                             NAZOAUTH_ADMIN_PROVISION_OPERATION_ID="initial-rp-account",
                             NAZOAUTH_ADMIN_PROVISION_DEPLOYMENT_ID=deployment)
        subprocess.run([str(binary), "admin-provision"], cwd=directory, env=provision_env,
                       check=True, stdout=log, stderr=log)
        credential_path.unlink()
        process = subprocess.Popen([str(binary), "server"], cwd=directory, env=env, stdout=log, stderr=log)
    private_json(directory / "process.json", {"pid": process.pid})
    context = ssl.create_default_context()
    for _ in range(90):
        if process.poll() is not None:
            raise RuntimeError("NazoAuth exited; inspect the private server log")
        try:
            with urllib.request.urlopen(origin + "/health", context=context, timeout=2) as response:
                if response.status == 200:
                    break
        except (OSError, urllib.error.URLError):
            time.sleep(1)
    else:
        process.terminate()
        raise RuntimeError("NazoAuth did not become ready")
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a") as output:
            output.write(f"OIDF_RP_SETTINGS={settings_path}\nOIDF_RP_ORIGIN={origin}\n")
            output.write(f"OIDF_RP_SERVER_PID={process.pid}\n")
    print("Production NazoAuth RP is ready at " + origin)


if __name__ == "__main__":
    main()
