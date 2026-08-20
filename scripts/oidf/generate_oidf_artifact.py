#!/usr/bin/env python3
"""Build and sign the pinned external OIDF artifact consumed by NazoAuthCtl."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import pathlib
import posixpath
import re
import stat
import subprocess
import tempfile
import time
import urllib.parse


ARTIFACT_ID = "nazoauth-oidf-v5.2.2-ordinary-provider"
ARTIFACT_REVISION = "ac846e9080a86e30210de84289488e312e27f35e"
SOURCE_REPOSITORY = "https://github.com/nazozero/NazoAuth.git"
SOURCE_COMMIT = "77c362f9fc62e5114f3c61e2b4420f864d7112ab"
SOURCE_PATH = "crates/authorization-server/resources/nazoauth-conformance-matrix-v1.json"
SOURCE_BLOB = "2539e92a02651259eedc5002b6e0cbfbedb16e68"
SUITE_RELEASE = "release-v5.2.2"
SUITE_REVISION = "321bc5bc53601b9690b54c023c0cbfac0f0230f2"
SUITE_IMAGE = "sha256:ca3fb5be36fc2f471942f474ad7ff40677f29d40ce7a9f7525db1102b89b0415"
GENERATOR_PREDECESSOR_SHA256 = (
    "dadd1d8c0dbe87b0c40a7ae8ec6569e3875d02a6aa5874d4ac307dab2d816ae9"
)
EXPECTED_DRIVER_SHA256 = "62b54d229e01bfb4a1b93c340a2e71839e492b83f53aff1b9792b38b71ea7a1a"
EXPECTED_DRIVER_SIZE = 461
EXPECTED_MATRIX_SHA256 = "93806b506e2e10c1dc261389d47f3f3a83dec56e68f3c1e3a3dbd6b29d9a4bc6"
EXPECTED_MATRIX_SIZE = 481746
EXPECTED_BOUNDS = {
    "max_plans": 44,
    "max_modules": 1408,
    "max_clients": 66,
    "max_wall_clock_seconds": 79200,
}
RUNNER_CAPABILITY = "nazoauth.client.create"
PLAN_MODULE_BUDGET = 32
PLAN_WALL_CLOCK_SECONDS = 1800
P256_COMPRESSED_SPKI_PREFIX = bytes.fromhex(
    "3039301306072a8648ce3d020106082a8648ce3d030107032200"
)
PUBLIC_OUTPUT_NAMES = frozenset(
    {"driver.json", "matrix.json", "manifest.jws", "trust-policy.json", "metadata.json"}
)
PROVENANCE_PATH = pathlib.Path(__file__).with_name("provenance-v5.2.2.json")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
CANONICAL_PATH = re.compile(r"/[A-Za-z0-9._~/-]*")


def compact_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def expected_provenance() -> dict[str, object]:
    return {
        "schema": 1,
        "artifact": {"artifact_id": ARTIFACT_ID, "revision": ARTIFACT_REVISION},
        "source_matrix": {
            "repository": SOURCE_REPOSITORY,
            "commit": SOURCE_COMMIT,
            "path": SOURCE_PATH,
            "git_blob": SOURCE_BLOB,
        },
        "suite": {
            "release": SUITE_RELEASE,
            "revision": SUITE_REVISION,
            "image_digest": SUITE_IMAGE,
        },
        "generator": {
            "path": "scripts/oidf/generate_oidf_artifact.py",
            "predecessor_sha256": GENERATOR_PREDECESSOR_SHA256,
            "reviewed_parent_commit": "cac041f0773058dbd3050593ca2361f20a04ed91",
            "host_checkout": "inject the exact reviewed generator commit from independent task evidence",
        },
        "expected_output": {
            "driver": {"sha256": EXPECTED_DRIVER_SHA256, "size": EXPECTED_DRIVER_SIZE},
            "matrix": {"sha256": EXPECTED_MATRIX_SHA256, "size": EXPECTED_MATRIX_SIZE},
            "resource_bounds": EXPECTED_BOUNDS,
        },
    }


def validate_provenance() -> None:
    try:
        provenance = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read pinned provenance: {error}") from error
    if provenance != expected_provenance():
        raise ValueError("pinned provenance does not match the generator trust anchors")


def canonical_https(value: str, *, directory: bool) -> str:
    if not value.isascii() or "\\" in value or "%" in value:
        raise ValueError("URL must be an unencoded canonical ASCII HTTPS URL")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("URL contains an invalid host or port") from error
    if parsed.scheme != "https" or parsed.hostname is None:
        raise ValueError("URL must use HTTPS and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are forbidden")
    if parsed.query or parsed.fragment:
        raise ValueError("URL query strings and fragments are forbidden")
    hostname = parsed.hostname
    if hostname != hostname.lower():
        raise ValueError("URL host must be lowercase")
    if ":" in hostname:
        try:
            address = ipaddress.IPv6Address(hostname)
        except ValueError as error:
            raise ValueError("URL contains an invalid IPv6 host") from error
        if address.compressed != hostname:
            raise ValueError("IPv6 host is not canonical")
        canonical_host = f"[{hostname}]"
    else:
        if hostname.replace(".", "").isdigit():
            try:
                address = ipaddress.IPv4Address(hostname)
            except ValueError as error:
                raise ValueError("URL contains an invalid IPv4 host") from error
            if str(address) != hostname:
                raise ValueError("IPv4 host is not canonical")
        elif len(hostname) > 253 or any(DNS_LABEL.fullmatch(label) is None for label in hostname.split(".")):
            raise ValueError("URL contains a non-canonical DNS host")
        canonical_host = hostname
    if port is not None:
        if port == 443:
            raise ValueError("the default HTTPS port must be omitted")
        canonical_host = f"{canonical_host}:{port}"
    if parsed.netloc != canonical_host:
        raise ValueError("URL authority is not canonical")
    if directory:
        if not parsed.path.startswith("/") or not parsed.path.endswith("/"):
            raise ValueError("artifact source must be an HTTPS directory URL ending in '/'")
        if CANONICAL_PATH.fullmatch(parsed.path) is None or "//" in parsed.path or (
            parsed.path != "/" and posixpath.normpath(parsed.path) + "/" != parsed.path
        ):
            raise ValueError("artifact source path is not canonical")
        canonical = urllib.parse.urlunsplit(("https", canonical_host, parsed.path, "", ""))
    else:
        if parsed.path:
            raise ValueError("Suite origin must not contain a path")
        canonical = urllib.parse.urlunsplit(("https", canonical_host, "", "", ""))
    if canonical != value:
        raise ValueError("URL is not canonical")
    return canonical


def run_git(repo: pathlib.Path, arguments: list[str]) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError(f"Git could not read the pinned NazoAuth source: {error}") from error


def read_source_matrix(repo: pathlib.Path) -> dict[str, object]:
    if not repo.is_dir():
        raise ValueError("--nazoauth-repo must name an existing Git worktree")
    origin = run_git(repo, ["remote", "get-url", "origin"]).decode("utf-8").strip()
    if origin != SOURCE_REPOSITORY:
        raise ValueError(f"NazoAuth origin must be exactly {SOURCE_REPOSITORY}")
    commit = run_git(repo, ["rev-parse", "--verify", f"{SOURCE_COMMIT}^{{commit}}"]).decode().strip()
    if commit != SOURCE_COMMIT:
        raise ValueError("the pinned NazoAuth commit resolved to an unexpected object")
    blob = run_git(repo, ["rev-parse", "--verify", f"{SOURCE_COMMIT}:{SOURCE_PATH}"]).decode().strip()
    if blob != SOURCE_BLOB:
        raise ValueError("the pinned NazoAuth matrix path has an unexpected Git blob")
    source_bytes = run_git(repo, ["cat-file", "blob", SOURCE_BLOB])
    try:
        source = json.loads(source_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("the pinned NazoAuth matrix blob is not valid UTF-8 JSON") from error
    if not isinstance(source, dict):
        raise ValueError("the pinned NazoAuth matrix root must be an object")
    return source


def fsync_directory(directory: pathlib.Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: pathlib.Path, value: bytes, mode: int) -> None:
    if path.exists() or path.is_symlink():
        current = path.lstat()
        if not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid():
            raise ValueError(f"refusing to replace unsafe output path: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def prepare_public_directory(path: pathlib.Path) -> None:
    if path.exists() or path.is_symlink():
        current = path.lstat()
        if not stat.S_ISDIR(current.st_mode) or path.is_symlink():
            raise ValueError("public output must be a non-symlink directory")
    else:
        path.mkdir(parents=True, mode=0o755)
    os.chmod(path, 0o755)
    unexpected = {entry.name for entry in path.iterdir()} - PUBLIC_OUTPUT_NAMES
    if unexpected:
        raise ValueError(f"public output contains unexpected entries: {sorted(unexpected)}")


def reject_symlink_components(path: pathlib.Path, label: str) -> pathlib.Path:
    absolute = pathlib.Path(os.path.abspath(path))
    for component in (absolute, *absolute.parents):
        try:
            current = component.lstat()
        except OSError as error:
            raise ValueError(f"could not inspect {label} path component: {component}") from error
        if stat.S_ISLNK(current.st_mode):
            raise ValueError(f"{label} path must not contain symlink components")
    return absolute


def verify_private_directory(path: pathlib.Path) -> None:
    if os.name != "posix":
        raise ValueError("artifact signing is supported only on a Unix host")
    absolute = reject_symlink_components(path, "private directory")
    current = absolute.lstat()
    if not stat.S_ISDIR(current.st_mode) or current.st_uid != os.geteuid():
        raise ValueError("private output directory must be owned by the current Unix user")
    if stat.S_IMODE(current.st_mode) != 0o700:
        raise ValueError("private output directory mode must be exactly 0700")


def verify_signing_key(path: pathlib.Path) -> None:
    if os.name != "posix":
        raise ValueError("artifact signing is supported only on a Unix host")
    absolute = reject_symlink_components(path, "signing key")
    verify_private_directory(absolute.parent)
    current = absolute.lstat()
    if not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid():
        raise ValueError("signing key must be a regular file owned by the current Unix user")
    if stat.S_IMODE(current.st_mode) & 0o077:
        raise ValueError("signing key must be owner-only")


def handler_for(group_id: str) -> tuple[str, dict[str, object]]:
    if group_id == "fapi-ciba":
        return "browser-ciba", {"id": "browser-ciba", "automation": {"kind": "browser"}, "lane": "ciba"}
    if group_id.startswith("openid4vc-vci"):
        return "openid4vci-parallel", {
            "id": "openid4vci-parallel",
            "automation": {"kind": "openid4vci"},
            "lane": "parallel",
        }
    if group_id == "openid4vc-vp-haip":
        return "openid4vp-haip-parallel", {
            "id": "openid4vp-haip-parallel",
            "automation": {"kind": "openid4vp", "haip": True},
            "lane": "parallel",
        }
    if group_id == "openid4vc-vp":
        return "openid4vp-parallel", {
            "id": "openid4vp-parallel",
            "automation": {"kind": "openid4vp", "haip": False},
            "lane": "parallel",
        }
    return "browser-parallel", {
        "id": "browser-parallel",
        "automation": {"kind": "browser"},
        "lane": "parallel",
    }


def transform_matrix(source: dict[str, object]) -> tuple[dict[str, object], dict[str, object], dict[str, int]]:
    groups: list[dict[str, object]] = []
    handlers: dict[str, dict[str, object]] = {}
    plan_count = 0
    client_count = 0
    for source_group in source["groups"]:
        group = dict(source_group)
        plans: list[dict[str, object]] = []
        handler_id, handler = handler_for(group["id"])
        handlers[handler_id] = handler
        for source_plan in group["plans"]:
            plan = dict(source_plan)
            required_roles = plan.get("required_roles", [])
            plan["driver_handler"] = handler_id
            plan["resource_budget"] = {
                "modules": PLAN_MODULE_BUDGET,
                "clients": len(required_roles),
                "wall_clock_seconds": PLAN_WALL_CLOCK_SECONDS,
            }
            plan["required_capabilities"] = [RUNNER_CAPABILITY]
            plan.setdefault("expected_results", {})
            plans.append(plan)
            plan_count += 1
            client_count += len(required_roles)
        group["plans"] = plans
        groups.append(group)

    matrix = {
        "schema": 3,
        "name": "NazoAuth ordinary-provider OIDF v5.2.2 matrix",
        "openid4vc_credential_datasets": source["openid4vc_credential_datasets"],
        "openid4vc_suite_mdoc_trust_anchor_pem": source["openid4vc_suite_mdoc_trust_anchor_pem"],
        "groups": groups,
    }
    driver = {
        "schema": 1,
        "engine_protocol": 2,
        "handlers": [handlers[key] for key in sorted(handlers)],
    }
    bounds = {
        "max_plans": plan_count,
        "max_modules": plan_count * PLAN_MODULE_BUDGET,
        "max_clients": client_count,
        "max_wall_clock_seconds": plan_count * PLAN_WALL_CLOCK_SECONDS,
    }
    return matrix, driver, bounds


def parse_der_integer(value: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(value) or value[offset] != 0x02:
        raise ValueError("ECDSA signature does not contain an INTEGER")
    length = value[offset + 1]
    start = offset + 2
    end = start + length
    if length == 0 or length > 33 or end > len(value):
        raise ValueError("ECDSA signature contains an invalid INTEGER")
    encoded = value[start:end]
    if encoded[0] & 0x80:
        raise ValueError("ECDSA signature contains a negative INTEGER")
    if len(encoded) > 1 and encoded[0] == 0 and not encoded[1] & 0x80:
        raise ValueError("ECDSA signature contains a redundant INTEGER prefix")
    if encoded == b"\x00":
        raise ValueError("ECDSA signature contains a zero INTEGER")
    return int.from_bytes(encoded, "big"), end


def p1363_signature(der: bytes) -> bytes:
    if len(der) < 8 or len(der) > 72 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("OpenSSL returned a non-canonical ECDSA signature")
    r, offset = parse_der_integer(der, 2)
    s, offset = parse_der_integer(der, offset)
    if offset != len(der) or r == 0 or s == 0 or r.bit_length() > 256 or s.bit_length() > 256:
        raise ValueError("OpenSSL returned an out-of-range ECDSA signature")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def compressed_public_key(key_path: pathlib.Path) -> bytes:
    try:
        encoded = subprocess.run(
            ["openssl", "ec", "-in", str(key_path), "-pubout", "-conv_form", "compressed", "-outform", "DER"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("OpenSSL could not derive the signing public key") from error
    if not encoded.startswith(P256_COMPRESSED_SPKI_PREFIX):
        raise ValueError("signing key is not a P-256 key with canonical compressed SPKI")
    point = encoded[len(P256_COMPRESSED_SPKI_PREFIX) :]
    if len(point) != 33 or point[0] not in (2, 3):
        raise ValueError("could not extract canonical compressed P-256 public key")
    return point


def sign(key_path: pathlib.Path, signing_input: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        input_path = root / "input"
        signature_path = root / "signature.der"
        input_path.write_bytes(signing_input)
        try:
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(key_path), "-out", str(signature_path), str(input_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            signature_der = signature_path.read_bytes()
            public_path = root / "public.pem"
            subprocess.run(
                ["openssl", "ec", "-in", str(key_path), "-pubout", "-out", str(public_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(public_path), "-signature", str(signature_path), str(input_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError("OpenSSL could not create and verify the artifact signature") from error
    return p1363_signature(signature_der)


def validate_deterministic_output(
    driver_bytes: bytes, matrix_bytes: bytes, revision: str, bounds: dict[str, int]
) -> None:
    actual = {
        "driver_sha256": sha256(driver_bytes),
        "driver_size": len(driver_bytes),
        "matrix_sha256": sha256(matrix_bytes),
        "matrix_size": len(matrix_bytes),
        "revision": revision,
        "bounds": bounds,
    }
    expected = {
        "driver_sha256": EXPECTED_DRIVER_SHA256,
        "driver_size": EXPECTED_DRIVER_SIZE,
        "matrix_sha256": EXPECTED_MATRIX_SHA256,
        "matrix_size": EXPECTED_MATRIX_SIZE,
        "revision": ARTIFACT_REVISION,
        "bounds": EXPECTED_BOUNDS,
    }
    if actual != expected:
        raise ValueError(f"deterministic artifact output drifted: expected {expected}, got {actual}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nazoauth-repo", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--trust-policy-output", required=True, type=pathlib.Path)
    parser.add_argument("--signing-key", required=True, type=pathlib.Path)
    parser.add_argument("--expected-key-id", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--suite-origin", required=True)
    args = parser.parse_args()

    validate_provenance()
    source_url = canonical_https(args.source, directory=True)
    suite_origin = canonical_https(args.suite_origin, directory=False)
    verify_signing_key(args.signing_key)
    verify_private_directory(args.trust_policy_output.parent)

    public_root = pathlib.Path(os.path.abspath(args.output))
    private_policy = pathlib.Path(os.path.abspath(args.trust_policy_output))
    signing_key = pathlib.Path(os.path.abspath(args.signing_key))
    if private_policy.parent == public_root or public_root in private_policy.parents:
        raise ValueError("private trust-policy output must be outside the public output directory")
    if signing_key == private_policy or signing_key == public_root or public_root in signing_key.parents:
        raise ValueError("signing key must be separate from all artifact outputs")

    source_matrix = read_source_matrix(args.nazoauth_repo)
    matrix, driver, bounds = transform_matrix(source_matrix)
    matrix_bytes = compact_json(matrix)
    driver_bytes = compact_json(driver)
    artifact_revision = sha256(driver_bytes + matrix_bytes)[:40]
    validate_deterministic_output(driver_bytes, matrix_bytes, artifact_revision, bounds)

    public_key = compressed_public_key(signing_key)
    key_id = f"oidf-es256-{sha256(public_key)[:32]}"
    if args.expected_key_id != key_id:
        raise ValueError(f"signing key ID mismatch: expected {args.expected_key_id}, derived {key_id}")

    issued_at = int(time.time()) - 5
    manifest = {
        "schema": 4,
        "artifact_id": ARTIFACT_ID,
        "revision": artifact_revision,
        "source": source_url,
        "signer_identity": f"{source_url}signer-v1",
        "issued_at": issued_at,
        "not_before": issued_at,
        "expires_at": issued_at + 30 * 24 * 60 * 60,
        "suite": {
            "origin": suite_origin,
            "release": SUITE_RELEASE,
            "revision": SUITE_REVISION,
            "image_digest": SUITE_IMAGE,
        },
        "engine_protocol": 2,
        "required_capabilities": [RUNNER_CAPABILITY],
        "driver": {
            "schema": 1,
            "url": f"{source_url}driver.json",
            "sha256": sha256(driver_bytes),
            "size": len(driver_bytes),
        },
        "matrix": {
            "schema": 3,
            "url": f"{source_url}matrix.json",
            "sha256": sha256(matrix_bytes),
            "size": len(matrix_bytes),
        },
        "resource_bounds": bounds,
    }
    header = compact_json({"alg": "ES256", "kid": key_id, "typ": "nazoauth-oidf-driver-manifest+jws"})
    payload = compact_json(manifest)
    signing_input = f"{b64url(header)}.{b64url(payload)}".encode("ascii")
    compact_manifest = signing_input + b"." + b64url(sign(signing_key, signing_input)).encode("ascii")

    trust_policy = {
        "schema": 1,
        "source": source_url,
        "signer_identity": manifest["signer_identity"],
        "key_id": key_id,
        "public_key_sec1": b64url(public_key),
    }
    trust_policy_bytes = compact_json(trust_policy) + b"\n"
    metadata = {
        "artifact_manifest_sha256": sha256(compact_manifest),
        "artifact_revision": artifact_revision,
        "driver_sha256": sha256(driver_bytes),
        "matrix_sha256": sha256(matrix_bytes),
        "key_id": key_id,
        "suite_revision": SUITE_REVISION,
        "suite_image_digest": SUITE_IMAGE,
    }

    # No output is mutated until all source, provenance, key and deterministic
    # artifact checks have completed successfully.
    prepare_public_directory(public_root)
    atomic_write(public_root / "driver.json", driver_bytes, 0o644)
    atomic_write(public_root / "matrix.json", matrix_bytes, 0o644)
    atomic_write(public_root / "manifest.jws", compact_manifest + b"\n", 0o644)
    atomic_write(public_root / "trust-policy.json", trust_policy_bytes, 0o644)
    atomic_write(public_root / "metadata.json", compact_json(metadata) + b"\n", 0o644)
    atomic_write(private_policy, trust_policy_bytes, 0o600)
    print(json.dumps(metadata, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
