# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import os
import subprocess
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class VerificationGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = (ROOT / ".github/workflows/verify.yml").read_text()
        step = workflow.split("      - name: Require all selected verifications to pass\n", 1)[1]
        cls.script = textwrap.dedent(step.split("        run: |\n", 1)[1])

    def gate(self, build="true", manifest="false", vm="success", feed="skipped", changes="success"):
        return subprocess.run(
            ["bash", "-c", self.script], capture_output=True, text=True,
            env={**os.environ, "BUILD_REQUIRED": build, "MANIFEST_CHANGED": manifest,
                 "VM_RESULT": vm, "MANIFEST_RESULT": feed, "CHANGES_RESULT": changes},
        )

    def test_manifest_only_vm_only_and_mixed_success(self):
        cases = [("false", "true", "skipped", "success"),
                 ("true", "false", "success", "skipped"),
                 ("true", "true", "success", "success")]
        for args in cases:
            with self.subTest(args=args):
                result = self.gate(*args)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_cancelled_or_skipped_required_checks_block_merge(self):
        for result in ("failure", "cancelled", "skipped", ""):
            with self.subTest(result=result):
                self.assertNotEqual(self.gate(vm=result).returncode, 0)
                self.assertNotEqual(self.gate("false", "true", "skipped", result).returncode, 0)
                self.assertNotEqual(self.gate("true", "true", result, "success").returncode, 0)
                self.assertNotEqual(self.gate("true", "true", "success", result).returncode, 0)

    def test_failed_classification_or_missing_outputs_cannot_pass(self):
        for result in ("failure", "cancelled", "skipped", ""):
            with self.subTest(result=result):
                self.assertNotEqual(self.gate(changes=result).returncode, 0)
        self.assertNotEqual(self.gate(build="").returncode, 0)
        self.assertNotEqual(self.gate(manifest="").returncode, 0)
        self.assertNotEqual(self.gate("false", "false", "skipped", "skipped").returncode, 0)


if __name__ == "__main__":
    unittest.main()
