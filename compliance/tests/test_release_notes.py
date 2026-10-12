# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "script"))

from release_notes import dependency_summary, render_release_notes, select_baseline


def package(name, version, role="runtime"):
    return {"name": name, "version": version, "role": role, "sha256": "a" * 64}


def lock(*packages):
    return {"alpine": {"version": "3.24.1"}, "packages": list(packages)}


def release(tag, date="2026-10-01T00:00:00Z", **kwargs):
    return {"tag_name": tag, "published_at": date, "draft": False,
            "prerelease": False, **kwargs}


class ReleaseNotesTests(unittest.TestCase):
    def test_kernel_update_is_visible_even_with_unchanged_iso(self):
        before = lock(package("linux-lts", "6.18.35-r0", "kernel"))
        after = lock(package("linux-lts", "6.18.36-r1", "kernel"))
        text = dependency_summary(before, after)
        self.assertIn("**Kernel (linux-lts): 6.18.35-r0 → 6.18.36-r1**", text)
        self.assertIn("| linux-lts | kernel | 6.18.35-r0 | 6.18.36-r1 | Version changed |", text)

    def test_package_changes_and_iso_to_apk_metadata_migration(self):
        before = lock(package("busybox", "1.37.0-r30"), package("removed", "1-r0"),
                      package("linux-lts", "6.18.35-r0", "kernel"))
        after = lock(package("busybox", "1.37.0-r31"), package("added", "2-r0"),
                     package("linux-lts", "6.18.35-r0", "kernel"))
        after["packages"][2]["sha256"] = "b" * 64
        text = dependency_summary(before, after)
        self.assertIn("| busybox | runtime | 1.37.0-r30 | 1.37.0-r31 | Version changed |", text)
        self.assertIn("| added | runtime | — | 2-r0 | Added |", text)
        self.assertIn("| removed | runtime | 1-r0 | — | Removed |", text)
        self.assertIn("| linux-lts | kernel | 6.18.35-r0 | 6.18.35-r0 | Metadata changed", text)

    def test_unchanged_and_initial_inventory(self):
        current = lock(package("busybox", "1.37.0-r31"))
        self.assertIn("No package version or package metadata changes.",
                      dependency_summary(copy.deepcopy(current), current))
        notes = render_release_notes(current, None, baseline=None, asset_version=1,
                                     commit="a" * 40)
        self.assertIn("First release", notes)
        self.assertIn("| busybox | runtime | — | 1.37.0-r31 | Included |", notes)
        self.assertIn("multi-license aggregate", notes)
        self.assertIn("VM asset version: 1.", notes)

    def test_baseline_ignores_latest_legacy_and_draft_retry(self):
        releases = [release("alpine-3.24.1-r2", "2026-10-12T00:00:00Z"),
                    release("V1-alpine-3.24.0-r9"),
                    release("V1-alpine-3.24.1-r1", "2026-10-02T00:00:00Z"),
                    release("V1-alpine-3.24.1-r2", draft=True),
                    release("V2-alpine-3.25.0-r1", prerelease=True)]
        self.assertEqual(select_baseline(releases[::-1], "V1-alpine-3.24.1-r2"),
                         "V1-alpine-3.24.1-r1")
        self.assertEqual(select_baseline(releases[:1], "V1-alpine-3.24.1-r1"),
                         "alpine-3.24.1-r2")
        self.assertIsNone(select_baseline([], "V1-alpine-3.24.1-r1"))

    def test_cli_reads_published_tag_lock_and_fails_if_tag_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=repo, text=True)
            git("init", "-q")
            (repo / "config").mkdir()
            path = repo / "config/packages.lock.json"
            path.write_text(json.dumps(lock(package("busybox", "1-r0"))))
            git("add", ".")
            git("-c", "user.name=Test", "-c", "user.email=test@example.com",
                "-c", "commit.gpgsign=false", "commit", "-qm", "initial")
            tag = "V1-alpine-3.24.1-r1"
            git("tag", tag)
            path.write_text(json.dumps(lock(package("busybox", "2-r0"))))
            releases = repo / "releases.json"
            releases.write_text(json.dumps([release(tag, target_commitish="main")]))
            command = [sys.executable, str(ROOT / "script/release_notes.py"),
                       "--lock", str(path), "--releases-json", str(releases),
                       "--release-tag", "V1-alpine-3.24.1-r2", "--release-commit", "a" * 40,
                       "--asset-version", "1"]
            result = subprocess.run(command, cwd=repo, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("| busybox | runtime | 1-r0 | 2-r0 |", result.stdout)
            self.assertIn(f"Compared with published release **{tag}**", result.stdout)
            git("tag", "-d", tag)
            result = subprocess.run(command, cwd=repo, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("First release", result.stdout)


if __name__ == "__main__":
    unittest.main()
