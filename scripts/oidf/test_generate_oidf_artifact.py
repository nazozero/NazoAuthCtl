"""Security regressions for the signed artifact source boundary."""
import copy
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import generate_oidf_artifact as generator

class GitSourceTest(unittest.TestCase):
    def test_ciba_amendment_preserves_protocol_requirements_and_other_profiles(self):
        bundled = pathlib.Path(__file__).resolve().parents[2] / "crates/nazoauthctl-conformance/resources/oidf/matrix.json"
        groups = json.loads(bundled.read_text(encoding="utf-8"))["groups"]
        generator.apply_reviewed_amendments(groups)
        expected = copy.deepcopy(groups)
        ciba = next(group for group in groups if group["id"] == "fapi-ciba")
        for plan in ciba["plans"]:
            for role in plan["required_roles"]:
                role["registration_template"]["security_policy"]["assurance"] = "fapi2"
        generator.apply_reviewed_amendments(groups)
        self.assertEqual(groups, expected)

    @unittest.skipUnless(os.name == "posix", "Unix artifact output permissions")
    def test_atomic_output_replaces_regular_files_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="oidf-output-") as directory:
            root = pathlib.Path(directory)
            output = root / "manifest.jws"
            generator.atomic_write(output, b"first", 0o600)
            generator.atomic_write(output, b"replacement", 0o600)
            self.assertEqual(output.read_bytes(), b"replacement")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            for destination in [output, root / "missing"]:
                link = root / "link"
                link.symlink_to(destination)
                with self.assertRaises(ValueError):
                    generator.atomic_write(link, b"must-not-write", 0o600)
                with self.assertRaises(ValueError):
                    generator.prepare_public_directory(link)
                link.unlink()
            self.assertEqual(output.read_bytes(), b"replacement")
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["manifest.jws"])

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
    def test_es256_signature_verifies_only_the_original_payload(self):
        with tempfile.TemporaryDirectory(prefix="oidf-signature-") as directory:
            root = pathlib.Path(directory)
            key = root / "key.pem"
            public = root / "public.pem"
            signature = root / "signature.der"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            payload = b"artifact-header.artifact-payload"
            raw = generator.sign(key, payload)
            self.assertEqual(len(raw), 64)
            integers = []
            for part in (raw[:32], raw[32:]):
                encoded = part.lstrip(b"\x00") or b"\x00"
                if encoded[0] & 0x80:
                    encoded = b"\x00" + encoded
                integers.append(b"\x02" + bytes([len(encoded)]) + encoded)
            sequence = b"".join(integers)
            signature.write_bytes(b"\x30" + bytes([len(sequence)]) + sequence)
            for data, expected in [(payload, 0), (payload + b"-changed", 1)]:
                result = subprocess.run(
                    ["openssl", "dgst", "-sha256", "-verify", str(public), "-signature", str(signature)],
                    input=data, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                )
                self.assertEqual(result.returncode, expected)

    def test_replace_refs_cannot_change_reviewed_source(self):
        # This is an empty temporary Git fixture, never a second project checkout.
        with tempfile.TemporaryDirectory(prefix="oidf-git-fixture-") as directory:
            repo = pathlib.Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE)
            git("init", "-q")
            for content in ["reviewed source", "unreviewed replacement"]:
                (repo / "matrix.json").write_text(content)
                git("add", "matrix.json")
                git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--no-gpg-sign", "-qm", content)
                if content == "reviewed source":
                    reviewed = git("rev-parse", "HEAD").decode().strip()
            replacement = git("rev-parse", "HEAD").decode().strip()
            git("replace", reviewed, replacement)
            self.assertEqual(git("show", reviewed + ":matrix.json"), b"unreviewed replacement")
            self.assertEqual(generator.run_git(repo, ["show", reviewed + ":matrix.json"]), b"reviewed source")

if __name__ == "__main__":
    unittest.main()
