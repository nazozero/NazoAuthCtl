#!/usr/bin/env python3
"""Generate a closed schema-2 recovery manifest and dynamic provider proof."""

from __future__ import annotations

import base64
import argparse
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROLES = (
    ("data_snapshot", "data-snapshot", "application/vnd.nazoauth.data-snapshot"),
    ("database_restore", "database-restore", "application/vnd.nazoauth.database-restore"),
    (
        "last_trusted_artifact",
        "last-trusted-artifact",
        "application/vnd.nazoauth.release-artifact",
    ),
    (
        "verification_material",
        "verification-material",
        "application/vnd.nazoauth.verification-material",
    ),
)


def compact(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def write_private_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(json.dumps(value, indent=2).encode("utf-8") + b"\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def generate_provider_identity(
    provider_key_path: Path,
) -> tuple[Ed25519PrivateKey, str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    provider_id = f"instance-{digest_bytes(public_key)[:32]}"
    provider_key_path.parent.mkdir(parents=True, exist_ok=True)
    provider_key_path.write_bytes(public_key)
    os.chmod(provider_key_path, 0o600)
    return private_key, provider_id, digest_bytes(public_key)


def generate_recovery_evidence(
    *,
    output_path: Path,
    artifact_root: Path,
    private_key: Ed25519PrivateKey,
    provider_id: str,
    deployment_id: str,
    release: str,
    lifecycle_sha256: str,
    operation: str,
) -> tuple[str, str]:
    if operation not in {"rehearse", "checkpoint", "restore"}:
        raise ValueError("unsupported recovery operation")
    artifact_root.mkdir(parents=True, exist_ok=True)
    contents = {
        "data_snapshot": b"controller-independent data snapshot\n",
        "database_restore": b"BEGIN;\nSELECT 1;\nCOMMIT;\n",
        "last_trusted_artifact": f"trusted release {release}\n".encode("utf-8"),
        "verification_material": b'{"schema":1,"verification":"closed-ci-fixture"}\n',
    }
    descriptors: dict[str, dict[str, Any]] = {}
    receipts: list[dict[str, Any]] = []
    for field, role, content_type in ROLES:
        artifact = artifact_root / f"{role}.bin"
        artifact.write_bytes(contents[field])
        os.chmod(artifact, 0o600)
        descriptor = {
            "role": role,
            "path": str(artifact),
            "sha256": digest_file(artifact),
            "size": artifact.stat().st_size,
            "content_type": content_type,
        }
        descriptors[field] = descriptor
        receipts.append(
            {
                "role": role,
                "sha256": descriptor["sha256"],
                "size": descriptor["size"],
                "content_type": content_type,
            }
        )

    manifest_sha256 = digest_bytes(compact([2, deployment_id, release, receipts]))
    issued_at = int(time.time())
    attestation = {
        "schema": 1,
        "provider_id": provider_id,
        "deployment_id": deployment_id,
        "release": release,
        "operation": operation,
        "manifest_sha256": manifest_sha256,
        "lifecycle_sha256": lifecycle_sha256,
        "artifacts": receipts,
        "nonce": b64url(os.urandom(24)),
        "issued_at": issued_at,
        "expires_at": issued_at + 300,
    }
    attestation["signature"] = b64url(private_key.sign(compact(attestation)))
    manifest = {
        "schema": 2,
        "deployment_id": deployment_id,
        "release": release,
        **descriptors,
        "provider_attestation": attestation,
    }
    write_private_json(output_path, manifest)


def bind_recovery_evidence(
    *,
    lifecycle_path: Path,
    output_path: Path,
    artifact_root: Path,
    provider_key_path: Path,
    deployment_id: str,
    release: str,
    operation: str,
) -> None:
    lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
    private_key, provider_id, provider_key_sha256 = generate_provider_identity(
        provider_key_path
    )
    lifecycle["recovery_providers"] = [
        {
            "provider_id": provider_id,
            "roles": [role for _, role, _ in ROLES],
            "verification_key": {
                "kind": "digest-bound-file",
                "path": str(provider_key_path),
                "sha256": provider_key_sha256,
            },
        }
    ]
    write_private_json(lifecycle_path, lifecycle)
    generate_recovery_evidence(
        output_path=output_path,
        artifact_root=artifact_root,
        private_key=private_key,
        provider_id=provider_id,
        deployment_id=deployment_id,
        release=release,
        lifecycle_sha256=digest_file(lifecycle_path),
        operation=operation,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lifecycle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--provider-key", type=Path, required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument(
        "--operation", choices=("rehearse", "checkpoint", "restore"), required=True
    )
    args = parser.parse_args()
    bind_recovery_evidence(
        lifecycle_path=args.lifecycle,
        output_path=args.output,
        artifact_root=args.artifact_root,
        provider_key_path=args.provider_key,
        deployment_id=args.deployment_id,
        release=args.release,
        operation=args.operation,
    )


if __name__ == "__main__":
    main()
