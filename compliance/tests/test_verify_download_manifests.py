# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "script"))
from download_manifest import REQUIRED_ASSETS, build_manifest
from verify_download_manifests import verification_plan, verify_downloads


class VerificationPlanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.git("init", "-q")
        self.git("config", "user.name", "Verification test")
        self.git("config", "user.email", "test@example.invalid")
        self.write("releases/v1.json", "{}")
        self.write("README.md", "original")
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", *args], stderr=subprocess.PIPE).decode().strip()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def plan(self, head, base=None):
        return verification_plan("pull_request", {"pull_request": {
            "base": {"sha": base or self.base}, "head": {"sha": head}}})

    def test_manifest_only_and_mixed_changes(self):
        self.write("releases/v1.json", '{"changed": true}')
        self.write("releases/v2.json", "{}")
        self.assertEqual(self.plan(self.commit()), {
            "build_required": False, "manifests": ["releases/v1.json", "releases/v2.json"]})
        self.write("script/example.py", "print('changed')")
        self.assertTrue(self.plan(self.commit())["build_required"])

    def test_non_manifest_changes_and_unusual_filenames_require_full_build(self):
        for name in ("README.md", "releases/v01.json", "releases/v0.json", "name\nwith\ttabs"):
            self.write(name, "changed")
        self.assertEqual(self.plan(self.commit()), {"build_required": True, "manifests": []})

    def test_deleted_or_renamed_feed_is_rejected(self):
        (self.root / "releases/v1.json").rename(self.root / "releases/v2.json")
        with self.assertRaisesRegex(ValueError, "only be added or modified"):
            self.plan(self.commit())

    def test_symlink_feed_is_rejected(self):
        path = self.root / "releases/v1.json"
        path.unlink()
        path.symlink_to("../README.md")
        with self.assertRaises(ValueError):
            self.plan(self.commit())

    def test_new_symlink_feed_is_rejected(self):
        (self.root / "releases/v2.json").symlink_to("../README.md")
        with self.assertRaisesRegex(ValueError, "regular"):
            self.plan(self.commit())

    def test_pr_uses_merge_base_not_unrelated_target_branch_changes(self):
        self.write("releases/v1.json", "changed")
        head = self.commit()
        self.git("checkout", "--detach", self.base)
        self.write("README.md", "target branch advance")
        base = self.commit()
        self.assertEqual(self.plan(head, base), {
            "build_required": False, "manifests": ["releases/v1.json"]})

    def test_push_checks_the_entire_pushed_range(self):
        self.write("README.md", "first pushed commit")
        self.commit()
        self.write("releases/v1.json", "second pushed commit")
        head = self.commit()
        self.assertEqual(verification_plan("push", {"before": self.base, "after": head}), {
            "build_required": True, "manifests": ["releases/v1.json"]})

    def test_manifest_only_push_uses_download_verification(self):
        self.write("releases/v1.json", "changed")
        self.assertEqual(verification_plan("push", {"before": self.base, "after": self.commit()}), {
            "build_required": False, "manifests": ["releases/v1.json"]})

    def test_manual_new_branch_and_empty_diff_keep_full_build(self):
        full = {"build_required": True, "manifests": []}
        self.assertEqual(verification_plan("workflow_dispatch", {}), full)
        self.assertEqual(verification_plan("push", {"before": "0" * 40, "after": self.base}), full)
        self.assertEqual(self.plan(self.base), full)

    def test_invalid_or_missing_refs_fail_instead_of_skipping_checks(self):
        with self.assertRaises(ValueError):
            self.plan("--stat")
        with self.assertRaises(subprocess.CalledProcessError):
            self.plan("f" * 40)
        with self.assertRaises(KeyError):
            verification_plan("pull_request", {})

    def test_plan_cli_emits_flags_and_does_not_emit_success_flags_on_error(self):
        self.write("releases/v1.json", "changed")
        event = self.root / "event.json"
        event.write_text(json.dumps({"before": self.base, "after": self.commit()}))
        output = self.root / "output"
        plan = self.root / "plan.json"
        env = {**os.environ, "GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": str(event),
               "GITHUB_OUTPUT": str(output)}
        command = [sys.executable, str(ROOT / "script/verify_download_manifests.py"),
                   "plan", "--plan", str(plan)]
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), "build_required=false\nmanifest_changed=true\n")
        output.write_text("")
        event.write_text("{}")
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), "")


class PublishedManifestTests(unittest.TestCase):
    def test_paginated_release_download_and_submitted_hash_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = Path.cwd()
            os.chdir(root)
            self.addCleanup(os.chdir, previous)
            source = root / "assets"
            source.mkdir()
            archive = source / "vm_assets.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("vm_assets/manifest.json", '{"assetVersion": 1}')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            (source / "SHA256SUMS").write_text(f"{digest}  vm_assets.zip\n")
            release = {
                "id": 2, "tag_name": "V1-alpine-3.24.3-r1", "created_at": "2026-10-27T00:00:00Z",
                "draft": False, "prerelease": False,
                "assets": [{"name": name, "size": (source / name).stat().st_size
                            if (source / name).exists() else 1} for name in REQUIRED_ASSETS],
            }
            older = dict(release, id=1, tag_name="V1-alpine-3.24.2-r1", created_at="2026-10-12T00:00:00Z")
            path = root / "releases/v1.json"
            path.parent.mkdir()
            manifest = build_manifest(release, 1, source)
            path.write_text(json.dumps(manifest))
            original = path.read_bytes()

            def download(command, **kwargs):
                self.assertEqual(command[:4], ["gh", "release", "download", release["tag_name"]])
                self.assertIn("example/assets", command)
                destination = Path(command[command.index("--dir") + 1])
                for name in ("vm_assets.zip", "SHA256SUMS"):
                    shutil.copyfile(source / name, destination / name)

            with patch("verify_download_manifests.subprocess.check_output",
                       return_value=json.dumps([[older], [release]]).encode()) as api, \
                    patch("verify_download_manifests.subprocess.run", side_effect=download):
                verify_downloads(["releases/v1.json"], "example/assets")
                self.assertEqual(path.read_bytes(), original)
                self.assertIn("--paginate", api.call_args.args[0])
                self.assertIn("--slurp", api.call_args.args[0])
                path.write_text(json.dumps(dict(manifest, sha256="0" * 64)))
                with self.assertRaisesRegex(ValueError, "sha256 mismatch"):
                    verify_downloads(["releases/v1.json"], "example/assets")
                path.write_text(json.dumps(dict(manifest, tagName=older["tag_name"])))
                with self.assertRaisesRegex(ValueError, "tagName mismatch"):
                    verify_downloads(["releases/v1.json"], "example/assets")


if __name__ == "__main__":
    unittest.main()
