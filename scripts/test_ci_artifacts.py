import unittest

from resolve_ci_run import select_artifacts, select_run


class CiArtifactsTests(unittest.TestCase):
    sha = "a" * 40
    repository = "nazozero/NazoAuthCtl"

    def successful(self, **changes):
        return dict(dict(id=1, head_sha=self.sha, head_branch="main", event="push",
                         head_repository={"full_name": self.repository},
                         status="completed", conclusion="success"), **changes)

    def test_only_successful_exact_source_is_accepted(self):
        self.assertEqual(select_run([self.successful()], self.sha, self.repository, True), 1)
        for changes in ({"head_sha": "b" * 40}, {"event": "pull_request"},
                        {"head_repository": {"full_name": "someone/fork"}},
                        {"status": "in_progress"}, {"conclusion": "failure"},
                        {"conclusion": "cancelled"}, {"head_branch": "feature"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                select_run([self.successful(**changes)], self.sha, self.repository, True)
        with self.assertRaises(ValueError):
            select_run([], self.sha, self.repository, True)
        with self.assertRaises(ValueError):
            select_run([self.successful()], "short", self.repository)

    def test_manual_compatibility_can_use_a_tested_branch_but_release_cannot(self):
        run = self.successful(event="workflow_dispatch", head_branch="feature")
        self.assertEqual(select_run([run], self.sha, self.repository), 1)
        with self.assertRaises(ValueError):
            select_run([run], self.sha, self.repository, True)

    def test_newer_failure_cannot_reuse_older_success(self):
        for change in ({"conclusion": "failure"}, {"status": "in_progress"}):
            with self.assertRaises(ValueError):
                select_run([self.successful(), self.successful(id=2, **change)], self.sha, self.repository)

    def test_artifact_ids_are_closed_and_expired_or_missing_assets_fail(self):
        targets = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
                   "x86_64-apple-darwin", "aarch64-apple-darwin")
        artifacts = [dict(id=index + 1, name=f"controller-{target}", expired=False)
                     for index, target in enumerate(targets)]
        self.assertEqual(select_artifacts(artifacts), dict(zip(targets, range(1, 5))))
        for bad in (artifacts[:-1], artifacts + [artifacts[0]],
                    [dict(artifacts[0], expired=True), *artifacts[1:]]):
            with self.assertRaises(ValueError):
                select_artifacts(bad)


if __name__ == "__main__":
    unittest.main()
