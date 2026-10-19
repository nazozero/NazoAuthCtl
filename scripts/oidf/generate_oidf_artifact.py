#!/usr/bin/env python3
"""Build and sign the external OIDF artifact consumed by NazoAuthCtl."""

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


RESOURCE_PATH = "crates/nazoauthctl-conformance/resources/oidf"
RUNNER_CAPABILITY = "nazoauth.client.create"
P256_COMPRESSED_SPKI_PREFIX = bytes.fromhex(
    "3039301306072a8648ce3d020106082a8648ce3d030107032200"
)
PUBLIC_OUTPUT_NAMES = frozenset(
    {"driver.json", "matrix.json", "manifest.jws", "trust-policy.json", "metadata.json"}
)
GENERATOR_REPO_PATH = "scripts/oidf/generate_oidf_artifact.py"
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
CANONICAL_PATH = re.compile(r"/[A-Za-z0-9._~/-]*")
LOWER_HEX_COMMIT = re.compile(r"[0-9a-f]{40}")


def compact_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
            ["git", "--no-replace-objects", "-C", str(repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError(f"Git could not read the required repository state: {error}") from error


def require_git_clean(repo: pathlib.Path, arguments: list[str], message: str) -> None:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repo), *arguments],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise ValueError("Git could not verify the generator checkout") from error
    if result.returncode != 0:
        raise ValueError(message)


def verify_generator_checkout(reviewed_commit: str) -> pathlib.Path:
    if LOWER_HEX_COMMIT.fullmatch(reviewed_commit) is None:
        raise ValueError("--reviewed-generator-commit must be 40 lowercase hexadecimal characters")

    script_path = reject_symlink_components(pathlib.Path(__file__), "generator")
    root_text = run_git(script_path.parent, ["rev-parse", "--show-toplevel"]).decode("utf-8").strip()
    root = pathlib.Path(root_text).resolve(strict=True)
    if script_path.relative_to(root).as_posix() != GENERATOR_REPO_PATH:
        raise ValueError("generator is not running from its fixed repository path")
    head = run_git(root, ["rev-parse", "--verify", "HEAD^{commit}"]).decode().strip()
    if head != reviewed_commit:
        raise ValueError("generator checkout HEAD does not equal the reviewed commit")
    require_git_clean(root, ["diff", "--quiet", "--"], "generator checkout has tracked worktree changes")
    require_git_clean(root, ["diff", "--cached", "--quiet", "--"], "generator checkout has staged changes")

    return root


def read_bundled_artifacts(repo: pathlib.Path, commit: str):
    driver_bytes = run_git(repo, ["show", f"{commit}:{RESOURCE_PATH}/driver.json"])
    matrix_bytes = run_git(repo, ["show", f"{commit}:{RESOURCE_PATH}/matrix.json"])
    suite = json.loads(run_git(repo, ["show", f"{commit}:{RESOURCE_PATH}/suite.json"]))
    matrix = json.loads(matrix_bytes)
    plans = [plan for group in matrix["groups"] for plan in group["plans"]]
    bounds = {
        "max_plans": len(plans),
        "max_modules": sum(plan["resource_budget"]["modules"] for plan in plans),
        "max_clients": sum(plan["resource_budget"]["clients"] for plan in plans),
        "max_wall_clock_seconds": sum(plan["resource_budget"]["wall_clock_seconds"] for plan in plans),
    }
    return driver_bytes, matrix_bytes, suite, bounds


def fsync_directory(directory: pathlib.Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: pathlib.Path, value: bytes, mode: int) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        pass
    else:
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
        temporary.unlink(missing_ok=True)


def prepare_public_directory(path: pathlib.Path) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        path.mkdir(parents=True, mode=0o755)
    else:
        if not stat.S_ISDIR(current.st_mode):
            raise ValueError("public output must be a non-symlink directory")
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
    absolute = reject_symlink_components(path, "signing key")
    verify_private_directory(absolute.parent)
    current = absolute.lstat()
    if not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid():
        raise ValueError("signing key must be a regular file owned by the current Unix user")
    if stat.S_IMODE(current.st_mode) & 0o077:
        raise ValueError("signing key must be owner-only")


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
    if offset != len(der) or r.bit_length() > 256 or s.bit_length() > 256:
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
    try:
        signature_der = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
            input=signing_input,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("OpenSSL could not create the artifact signature") from error
    return p1363_signature(signature_der)


def derived_metadata(
    driver_bytes: bytes, matrix_bytes: bytes, revision: str, bounds: dict[str, int]
) -> dict[str, object]:
    return {
        "driver": {"sha256": sha256(driver_bytes), "size": len(driver_bytes)},
        "matrix": {"sha256": sha256(matrix_bytes), "size": len(matrix_bytes)},
        "revision": revision,
        "bounds": bounds,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--trust-policy-output", type=pathlib.Path)
    parser.add_argument("--signing-key", type=pathlib.Path)
    parser.add_argument("--expected-key-id")
    parser.add_argument("--reviewed-generator-commit", required=True)
    parser.add_argument("--source")
    parser.add_argument("--suite-origin")
    parser.add_argument("--print-derived-metadata", action="store_true")
    args = parser.parse_args()

    signing_arguments = {
        "--output": args.output,
        "--trust-policy-output": args.trust_policy_output,
        "--signing-key": args.signing_key,
        "--expected-key-id": args.expected_key_id,
        "--source": args.source,
        "--suite-origin": args.suite_origin,
    }
    if args.print_derived_metadata:
        supplied = sorted(name for name, value in signing_arguments.items() if value is not None)
        if supplied:
            parser.error(f"--print-derived-metadata forbids signing/output arguments: {', '.join(supplied)}")
    else:
        missing = sorted(name for name, value in signing_arguments.items() if value is None)
        if missing:
            parser.error(f"normal signing mode requires: {', '.join(missing)}")

    repo = verify_generator_checkout(args.reviewed_generator_commit)
    driver_bytes, matrix_bytes, suite, bounds = read_bundled_artifacts(
        repo, args.reviewed_generator_commit
    )
    revision_digest = hashlib.sha256(driver_bytes)
    revision_digest.update(matrix_bytes)
    artifact_revision = revision_digest.hexdigest()[:40]
    computed = derived_metadata(driver_bytes, matrix_bytes, artifact_revision, bounds)
    if args.print_derived_metadata:
        print(
            json.dumps(
                computed,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return

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

    public_key = compressed_public_key(signing_key)
    key_id = f"oidf-es256-{sha256(public_key)[:32]}"
    if args.expected_key_id != key_id:
        raise ValueError(f"signing key ID mismatch: expected {args.expected_key_id}, derived {key_id}")

    issued_at = int(time.time()) - 5
    manifest = {
        "schema": 4,
        "artifact_id": f"nazoauth-oidf-{suite['release'].removeprefix('release-')}-ordinary-provider",
        "revision": artifact_revision,
        "source": source_url,
        "signer_identity": f"{source_url}signer-v1",
        "issued_at": issued_at,
        "not_before": issued_at,
        "expires_at": issued_at + 30 * 24 * 60 * 60,
        "suite": {
            "origin": suite_origin,
            **suite,
        },
        "engine_protocol": 2,
        "required_capabilities": [RUNNER_CAPABILITY],
        "driver": {
            "schema": 1,
            "url": f"{source_url}driver.json",
            **computed["driver"],
        },
        "matrix": {
            "schema": 3,
            "url": f"{source_url}matrix.json",
            **computed["matrix"],
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
        "driver_sha256": computed["driver"]["sha256"],
        "matrix_sha256": computed["matrix"]["sha256"],
        "key_id": key_id,
        "suite_revision": suite["revision"],
        "suite_image_digest": suite["image_digest"],
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
