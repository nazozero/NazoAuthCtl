#!/usr/bin/env python3
"""Export original Suite outcomes, redacting disposable fixture credentials."""

import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

SENSITIVE = {
    "client_secret", "password", "access_token", "refresh_token", "id_token", "id_token_hint",
    "authorization_code", "code", "code_verifier", "nonce", "state", "csrf_token", "session_id",
    "authorization", "cookie", "set-cookie", "logout_token", "verifiable_jws",
    "all_issued_id_tokens", "issued_id_tokens", "incoming_body", "outgoing",
    "d", "p", "q", "dp", "dq", "qi", "oth", "k", "key",
}
COMPACT_JOSE = re.compile(r"eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*){2,4}")
PEM_PRIVATE = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S)


def export(root):
    settings = root / "sut" / "rp-settings.json"
    secrets = []
    if settings.is_file():
        config = json.loads(settings.read_text())
        secrets = [config["client_secret"], config["account"]["password"]]
    suite_token = root / "suite-token.json"
    if suite_token.is_file():
        secrets.append(json.loads(suite_token.read_text())["token"])
    server_config = root / "sut" / ".env.yaml"
    if server_config.is_file():
        config = json.loads(server_config.read_text())
        database = config["DATABASE_URL"]
        secrets.extend([database, urlsplit(database).password, config["SIGNING_KEY_ENCRYPTION_KEY"]])

    def redact(value):
        if isinstance(value, dict):
            return {
                COMPACT_JOSE.sub("[redacted]", key): "[redacted]" if key.lower() in SENSITIVE else redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [redact(item) for item in value]
        if not isinstance(value, str):
            return value
        if value.lstrip().startswith(("{", "[")):
            try:
                return json.dumps(redact(json.loads(value)), ensure_ascii=False)
            except json.JSONDecodeError:
                pass
        if value.startswith(("https://", "http://")):
            parts = urlsplit(value)
            value = parts._replace(query="", fragment="").geturl()
        for secret in secrets:
            value = value.replace(secret, "[redacted]")
        return COMPACT_JOSE.sub("[redacted]", PEM_PRIVATE.sub("[redacted private key]", value))

    output = root / "evidence"
    output.mkdir(parents=True, exist_ok=True)
    metadata = {
        "policy": "Original Suite statuses, results and conditions are preserved. Temporary credentials, private keys, token values and protocol URL queries are redacted only in this exported copy.",
        "source_files": [],
    }
    private = root / "private-rp-evidence"
    if private.is_dir():
        for path in sorted(private.glob("*.json")):
            data = path.read_bytes()
            metadata["source_files"].append({"file": path.name, "original_sha256": hashlib.sha256(data).hexdigest()})
            (output / path.name).write_text(json.dumps(redact(json.loads(data)), indent=2) + "\n")
    log = root / "sut" / "server-private.log"
    if log.is_file():
        # Native diagnostics are supplementary; raw Suite module logs carry the
        # authoritative test outcomes above.
        (output / "server-log.txt").write_text(redact(log.read_text(errors="replace")))
    (output / "export-policy.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    export(Path(sys.argv[1]))
