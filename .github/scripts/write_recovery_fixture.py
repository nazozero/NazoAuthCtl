#!/usr/bin/env python3
"""Write a closed, secret-free controller recovery fixture for CI black-box tests."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def absolute_file(value: str, name: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ValueError(f"{name} must be an absolute regular file")
    return path


def absolute_directory(value: str, name: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be absolute")
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("spec", type=Path)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding="utf-8"))

    backend = spec["backend"]
    if backend not in {"docker", "podman", "systemd"}:
        raise ValueError("unsupported fixture backend")
    deployment_id = spec["deployment_id"]
    runtime_id = spec["runtime_id"]
    release = spec["release"]
    if not release.startswith("v"):
        raise ValueError("fixture release must be an immutable tag")

    config_root = absolute_directory(spec["config_root"], "config_root")
    state_root = absolute_directory(spec["state_root"], "state_root")
    absolute_directory(spec["break_glass_root"], "break_glass_root")
    identity_file = absolute_file(spec["identity_file"], "identity_file")
    identity = json.loads(identity_file.read_text(encoding="utf-8"))
    if identity["release"] != release:
        raise ValueError("embedded identity release differs from the fixture release")

    deployment_config = config_root / "deployments" / deployment_id
    deployment_state = state_root / "deployments" / deployment_id
    recovery_root = deployment_state / "recovery"
    identity_root = deployment_state / "identities"
    for path in (
        deployment_config,
        identity_root,
        deployment_state / "audit",
        deployment_state / "transactions",
        recovery_root,
    ):
        path.mkdir(parents=True, exist_ok=True)

    recovery_manifest = recovery_root / "manual-manifest.json"
    write_json(
        recovery_manifest,
        {"schema": 1, "fixture": "external resources remain external"},
    )
    recovery_sha = sha256(recovery_manifest)

    driver = recovery_root / "recovery-driver.py"
    driver.write_text(
        """#!/usr/bin/env python3
import json, pathlib, sys, time
request = json.load(sys.stdin)
marker = pathlib.Path(__file__).with_name("driver-invocations")
with marker.open("a", encoding="utf-8") as output:
    output.write(request["operation"] + "\\n")
json.dump({
    "schema": request["schema"],
    "request_id": request["request_id"],
    "deployment_id": request["deployment_id"],
    "release": request["release"],
    "operation": request["operation"],
    "lifecycle_sha256": request["lifecycle_sha256"],
    "recovery_manifest_sha256": request["recovery_manifest_sha256"],
    "status": "succeeded",
    "components": ["artifact", "verification"],
    "issued_at": int(time.time())
}, sys.stdout, separators=(",", ":"))
""",
        encoding="utf-8",
    )
    os.chmod(driver, 0o500)

    lifecycle = {
        "schema": 2,
        "deployment_id": deployment_id,
        "runtimes": [
            {
                "runtime_instance_id": runtime_id,
                "backend": backend,
                "object_reference": spec["object_reference"],
                **spec["runtime"],
            }
        ],
        "recovery_driver": {
            "program": str(driver),
            "program_sha256": sha256(driver),
            "arguments": [],
            "rehearsal_workspace": str(recovery_root / "rehearsal"),
            "credentials": {},
        },
    }
    lifecycle_path = recovery_root / "lifecycle.json"
    write_json(lifecycle_path, lifecycle)

    audit_key = identity_root / "audit.key"
    audit_key.write_text(
        base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii"),
        encoding="ascii",
    )
    os.chmod(audit_key, 0o600)

    artifact = spec["artifact"]
    cache_directory = recovery_root / "trusted-runtime" / release / runtime_id
    cache_directory.mkdir(parents=True, exist_ok=True)
    if artifact["kind"] == "oci":
        archive = absolute_file(artifact["archive"], "OCI archive")
        cache_artifact = {
            "kind": "oci-archive",
            "image_reference": artifact["image_reference"],
            "digest": artifact["digest"],
            "local_image_id": artifact["local_image_id"],
            "archive": str(archive),
            "archive_sha256": sha256(archive),
        }
        declared_artifact = {
            "kind": "oci",
            "image_reference": artifact["image_reference"],
            "digest": artifact["digest"],
        }
        local_artifact_id: str | None = artifact["local_image_id"]
    elif artifact["kind"] == "host":
        cached_binary = absolute_file(artifact["cached_binary"], "cached binary")
        digest = sha256(cached_binary)
        if digest != artifact["sha256"]:
            raise ValueError("cached host binary differs from its declared digest")
        cache_artifact = {
            "kind": "host-binary",
            "binary": str(cached_binary),
            "sha256": digest,
        }
        declared_artifact = {
            "kind": "host-binary",
            "path": artifact["target_path"],
            "sha256": digest,
        }
        local_artifact_id = None
    else:
        raise ValueError("unsupported fixture artifact")

    write_json(
        cache_directory.parent / "cache.json",
        {
            "schema": 2,
            "deployment_id": deployment_id,
            "release": identity,
            "runtimes": {runtime_id: cache_artifact},
        },
    )
    write_json(
        recovery_root / "rollback-slot.json",
        {
            "schema": 1,
            "deployment_id": deployment_id,
            "trusted_release": identity,
            "recovery_manifest": str(recovery_manifest),
            "recovery_manifest_sha256": recovery_sha,
        },
    )

    declaration = deployment_config / "deployment.json"
    write_json(
        declaration,
        {
            "schema": 1,
            "deployment_id": deployment_id,
            "control_authority": f"controller-{deployment_id}",
            "alias": spec["alias"],
            "issuer": spec["issuer"],
            "active_release": identity,
            "trust": "adopted",
            "capabilities": {
                "runtime": {"responsibility": "delegated", "scope": "deployment"},
                "artifact": {"responsibility": "delegated", "scope": "deployment"},
                "server_config": {"responsibility": "external", "scope": "deployment"},
                "database": {
                    "responsibility": spec.get("database_responsibility", "external"),
                    "scope": "shared",
                },
                "valkey": {"responsibility": "external", "scope": "shared"},
                "operator_tasks": {
                    "responsibility": spec.get("operator_tasks_responsibility", "external"),
                    "scope": "deployment",
                },
                "backups": {"responsibility": "delegated", "scope": "deployment"},
                "proxy_tls": {"responsibility": "external", "scope": "shared"},
            },
            "runtime_instances": [
                {
                    "runtime_instance_id": runtime_id,
                    "backend": backend,
                    "object_reference": spec["object_reference"],
                    "artifact": declared_artifact,
                    "local_artifact_id": local_artifact_id,
                    "ports": spec["declared_ports"],
                    "networks": spec["runtime"]["networks"],
                    "mounts": spec["runtime"]["mounts"],
                    "instance_key_id": None,
                    "deployment_statement": None,
                }
            ],
            "resources": {
                "audit_private_key": {"kind": "file", "path": str(audit_key)},
                "lifecycle_contract": {"kind": "file", "path": str(lifecycle_path)},
                "database": {"kind": "provider", "provider": "external-postgres", "key": deployment_id},
                "valkey": {"kind": "provider", "provider": "external-valkey", "key": deployment_id},
            },
            "recovery": {
                "conclusion": "proven",
                "evidence": ["ci-offline-cache"],
                "off_host_package_required_for_machine_loss": True,
            },
            "operator_protocol_versions": spec.get("operator_protocol_versions", [1]),
            "control_protocol_versions": [1],
            "declaration_revision": 1,
        },
    )
    write_json(
        config_root / "registry.json",
        {
            "schema": 1,
            "deployments": {
                deployment_id: {"alias": spec["alias"], "declaration": str(declaration)}
            },
        },
    )


if __name__ == "__main__":
    main()
