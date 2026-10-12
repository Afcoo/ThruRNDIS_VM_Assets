# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        # Execute the actual first step, without adding a YAML dependency to CI.
        cls.first_step = workflow.split("    steps:\n", 1)[1].split("\n      - name:", 1)[0]
        cls.script = textwrap.dedent(cls.first_step.split("        run: |\n", 1)[1])

    def run_guard(self, ref, default_branch="main"):
        # No checkout exists when this guard runs.
        with tempfile.TemporaryDirectory() as directory:
            return subprocess.run(
                ["bash", "-c", self.script], cwd=directory,
                env={**os.environ, "GITHUB_REF": ref, "GITHUB_REF_NAME": default_branch,
                     "DEFAULT_BRANCH": default_branch},
                capture_output=True, text=True,
            )

    def test_guard_is_first_and_uses_repository_default_branch(self):
        self.assertIn("- name: Require default branch", self.first_step)
        self.assertIn("DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}", self.first_step)
        self.assertNotIn("uses:", self.first_step)

    def test_main_branch_is_allowed(self):
        result = self.run_guard("refs/heads/main")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_renamed_default_branch_is_allowed(self):
        result = self.run_guard("refs/heads/stable/release", "stable/release")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.run_guard("refs/heads/main", "stable/release").returncode, 0)

    def test_other_branches_tags_and_pull_refs_fail_explicitly(self):
        for ref in ("refs/heads/feature/test", "refs/heads/main-other",
                    "refs/tags/main", "refs/pull/11/merge"):
            with self.subTest(ref=ref):
                result = self.run_guard(ref)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("::error::", result.stderr)
                self.assertIn(ref, result.stderr)


if __name__ == "__main__":
    unittest.main()
