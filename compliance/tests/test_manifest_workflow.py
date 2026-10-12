# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "example/assets"
BRANCH = "automation/download-manifest-V1-alpine-3.24.2-r1"
MANIFEST = '{"assetVersion": 1}\n'


@unittest.skipUnless(shutil.which("jq"), "workflow requires jq")
class ManifestWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = (ROOT / ".github/workflows/update-download-manifest.yml").read_text()
        step = workflow.split("      - name: Propose the verified manifest in a pull request\n", 1)[1]
        cls.script = textwrap.dedent(step.split("        run: |\n", 1)[1])

    def pull_request(self, branch=BRANCH, repository=REPOSITORY):
        return {"html_url": "https://example.invalid/pull/42",
                "head": {"ref": branch, "repo": {"full_name": repository}}}

    def run_proposal(self, pages, expected_branch, files="releases/v1.json", content=MANIFEST):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "releases").mkdir()
            (root / "releases/v1.json").write_text(MANIFEST)
            fixture = {"pages": pages, "files": files, "content": content,
                       "expected_branch": expected_branch}
            (root / "fixture.json").write_text(json.dumps(fixture))
            # Only external responses are mocked: execute the real shell and jq selection.
            gh = root / "gh"
            gh.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
                import base64
                import json
                import sys
                from pathlib import Path

                args = sys.argv[1:]
                fixture = json.loads(Path("fixture.json").read_text())
                with Path("calls.jsonl").open("a") as calls:
                    calls.write(json.dumps(args) + "\\n")
                if args[:1] == ["api"] and "repos/example/assets/pulls" in args:
                    assert "--paginate" in args
                    assert all(value in args for value in ("state=open", "base=main", "per_page=100"))
                    for page in fixture["pages"]:
                        print(json.dumps(page))
                elif args[:2] == ["pr", "view"]:
                    print(fixture["files"])
                elif args[:1] == ["api"] and args[1].startswith("repos/example/assets/contents/"):
                    expected = "repos/example/assets/contents/releases/v1.json?ref=" + fixture["expected_branch"]
                    assert args[1] == expected, args
                    print(base64.b64encode(fixture["content"].encode()).decode())
                else:
                    raise SystemExit("Unexpected GitHub call: " + repr(args))
                '''))
            gh.chmod(0o755)
            git = root / "git"
            git.write_text('#!/bin/sh\ncase "$1" in\n'
                           '  cat-file) exit 0 ;;\n'
                           '  diff) exit 1 ;;\n'
                           '  *) echo "Unexpected git call: $*" >&2; exit 90 ;;\nesac\n')
            git.chmod(0o755)
            result = subprocess.run(
                ["bash", "-c", self.script], cwd=root, text=True, capture_output=True,
                env={**os.environ, "PATH": f"{root}{os.pathsep}{os.environ['PATH']}",
                     "VM_ASSET_VERSION": "1", "RELEASE_TAG": "V1-alpine-3.24.2-r1",
                     "DEFAULT_BRANCH": "main", "GITHUB_REPOSITORY": REPOSITORY,
                     "RUNNER_TEMP": directory},
            )
            calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
            return result, calls

    def test_reuses_original_branch(self):
        result, _ = self.run_proposal([[self.pull_request()]], BRANCH)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Existing manifest PR:", result.stdout)

    def test_reuses_retry_branch_from_later_page_and_reads_that_branch(self):
        branch = BRANCH + "-100-2"
        decoys = [self.pull_request(repository="fork/assets"),
                  self.pull_request(branch=BRANCH + "0"),
                  self.pull_request(branch=BRANCH + "-unrelated")]
        result, _ = self.run_proposal([decoys, [self.pull_request(branch=branch)]], branch)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Existing manifest PR:", result.stdout)

    def test_rejects_retry_pr_with_other_files(self):
        branch = BRANCH + "-100-2"
        result, _ = self.run_proposal([[self.pull_request(branch=branch)]], branch,
                                      files="releases/v1.json\nREADME.md")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Existing PR changes files outside the manifest", result.stderr)

    def test_rejects_retry_pr_with_different_manifest_bytes(self):
        branch = BRANCH + "-100-2"
        result, calls = self.run_proposal([[self.pull_request(branch=branch)]], branch,
                                          content='{"assetVersion": 2}\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differ", result.stdout)
        self.assertTrue(any("/contents/" in " ".join(call) for call in calls))

    def test_rejects_ambiguous_existing_prs_before_reading_or_writing(self):
        result, calls = self.run_proposal(
            [[self.pull_request(), self.pull_request(branch=BRANCH + "-100-2")]], BRANCH)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Multiple open manifest PRs", result.stderr)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
