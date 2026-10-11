"""Security regressions for the signed artifact source boundary."""
import pathlib
import subprocess
import tempfile
import unittest
import generate_oidf_artifact as generator

class GitSourceTest(unittest.TestCase):
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
                git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", content)
                if content == "reviewed source":
                    reviewed = git("rev-parse", "HEAD").decode().strip()
            replacement = git("rev-parse", "HEAD").decode().strip()
            git("replace", reviewed, replacement)
            self.assertEqual(git("show", reviewed + ":matrix.json"), b"unreviewed replacement")
            self.assertEqual(generator.run_git(repo, ["show", reviewed + ":matrix.json"]), b"reviewed source")

if __name__ == "__main__":
    unittest.main()
