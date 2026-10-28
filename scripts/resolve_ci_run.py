"""Resolve tested controller artifacts; never substitute a different commit."""

import argparse
import json
import os
import re
import subprocess


def select_run(runs, sha, repository, require_main=False):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("expected a full controller commit SHA")
    matching = [run for run in runs if
                run.get("head_sha") == sha
                and run.get("head_repository", {}).get("full_name") == repository
                and run.get("event") in ("push", "workflow_dispatch")
                and (not require_main or run.get("head_branch") == "main")]
    latest = max(matching, key=lambda run: run["id"], default=None)
    if not latest or latest.get("status") != "completed" or latest.get("conclusion") != "success":
        raise ValueError(f"controller-ci must finish successfully for {sha}")
    return latest["id"]


def select_artifacts(artifacts):
    selected = {}
    for target in ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
                   "x86_64-apple-darwin", "aarch64-apple-darwin"):
        matches = [item for item in artifacts
                   if item.get("name") == f"controller-{target}" and item.get("expired") is False]
        if len(matches) != 1 or type(matches[0].get("id")) is not int or matches[0]["id"] <= 0:
            raise ValueError(f"missing unexpired controller-{target}; run controller-ci again for this commit")
        selected[target] = matches[0]["id"]
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sha")
    parser.add_argument("--require-main", action="store_true")
    args = parser.parse_args()
    repository = os.environ["GITHUB_REPOSITORY"]
    response = json.loads(subprocess.check_output([
        "gh", "api", "--method", "GET",
        f"/repos/{repository}/actions/workflows/ci.yml/runs",
        "-f", f"head_sha={args.sha}", "-F", "per_page=100",
    ], text=True))
    run_id = select_run(response["workflow_runs"], args.sha, repository, args.require_main)
    artifacts = json.loads(subprocess.check_output([
        "gh", "api", f"/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100",
    ], text=True))
    print(f"run_id={run_id}")
    print("artifact_ids=" + json.dumps(select_artifacts(artifacts["artifacts"]), separators=(",", ":")))


if __name__ == "__main__":
    main()
