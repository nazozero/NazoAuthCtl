"""Run the released executable against frozen old data, without changing that data."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
fixtures = Path(__file__).resolve().parents[1] / "tests/fixtures/persistence"
for version in sorted(fixtures.iterdir()):
    if not version.is_dir():
        continue
    with tempfile.TemporaryDirectory(prefix="ctl-upgrade-") as temporary:
        root = Path(temporary)
        scope = root / "target/deployments/deploy-upgrade"
        backup = scope / "backup"
        backup.mkdir(parents=True, mode=0o700)
        for source, destination in (
            (version / "state.json", scope / "state.json"),
            (version / "snapshot-manifest.json", backup / "snapshot-manifest.json"),
        ):
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o600)
        before = {path: hashlib.sha256(path.read_bytes()).digest() for path in scope.rglob("*.json")}
        environment = dict(os.environ, XDG_CONFIG_HOME=str(root / "config"),
                           APPDATA=str(root / "config"), NAZOAUTHCTL_TARGET_STATE_ROOT=str(root / "target"))
        result = subprocess.run([binary, "--json", "self", "verify-state"], env=environment,
                                capture_output=True, text=True, timeout=30, check=True)
        report = json.loads(result.stdout)
        assert report == {"schema": 1, "compatible": True, "deployments": 1}, report
        assert all(hashlib.sha256(path.read_bytes()).digest() == digest for path, digest in before.items())
        print(f"{version.name}: deployment and backup readable; original bytes preserved")
