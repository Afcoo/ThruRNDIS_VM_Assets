# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "script"))
from download_manifest import REQUIRED_ASSETS, build_manifest, select_release, verify_manifest


class DownloadManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        archive = self.directory / "vm_assets.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("vm_assets/manifest.json", json.dumps({"assetVersion": 1}))
        self.sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.directory / "SHA256SUMS").write_text(f"{self.sha256}  vm_assets.zip\n")
        self.release = {
            "id": 1, "tag_name": "V1-alpine-3.24.2-r1", "created_at": "2026-10-12T00:00:00Z",
            "draft": False, "prerelease": False,
            "assets": [{"name": name, "size": (self.directory / name).stat().st_size
                        if name in ("vm_assets.zip", "SHA256SUMS") else 1} for name in REQUIRED_ASSETS],
        }

    def test_manifest_has_only_consumer_fields(self):
        manifest = build_manifest(self.release, 1, self.directory)
        self.assertEqual(set(manifest), {"schemaVersion", "assetVersion", "tagName", "size", "sha256"})
        self.assertEqual(manifest["sha256"], self.sha256)

    def test_selects_by_created_at_and_ignores_incompatible_or_unpublished(self):
        newer = copy.deepcopy(self.release)
        newer.update(id=2, tag_name="V1-alpine-3.24.2-r2", created_at="2026-10-13T00:00:00Z")
        excluded = [dict(newer, id=3, draft=True), dict(newer, id=4, prerelease=True),
                    dict(newer, id=5, tag_name="V2-alpine-3.24.2-r1")]
        self.assertEqual(select_release([self.release, newer] + excluded, 1), newer)

    def test_non_release_tags_cannot_override_the_feed(self):
        for tag in ("V1-test", "V1-../bad", "V1-alpine-3.24.2-r0", "V1-alpine-3.24.2-r01",
                    "V1-alpine-3.24-r1", "V1-alpine-3.24.2-r1-extra",
                    "V1-alpine-3.24.2-r2\n"):
            with self.subTest(tag=tag):
                invalid = dict(self.release, id=2, tag_name=tag,
                               created_at="2026-10-13T00:00:00Z")
                self.assertEqual(select_release([self.release, invalid], 1), self.release)
                with self.assertRaises(ValueError):
                    select_release([invalid], 1)

    def test_incomplete_newest_release_does_not_fall_back(self):
        broken = dict(self.release, id=2, assets=[])
        with self.assertRaises(ValueError):
            select_release([self.release, broken], 1)

    def test_rejects_invalid_channel(self):
        for version in (True, 0, -1):
            with self.assertRaises(ValueError):
                select_release([self.release], version)

    def test_rejects_size_digest_and_checksum_mismatch(self):
        for field, value in (("size", 1), ("digest", "sha256:" + "0" * 64)):
            altered = copy.deepcopy(self.release)
            next(asset for asset in altered["assets"] if asset["name"] == "vm_assets.zip")[field] = value
            with self.assertRaises(ValueError):
                build_manifest(altered, 1, self.directory)
        (self.directory / "SHA256SUMS").write_text("0" * 64 + "  vm_assets.zip\n")
        with self.assertRaises(ValueError):
            build_manifest(self.release, 1, self.directory)

    def test_rejects_duplicate_checksum_and_wrong_embedded_version(self):
        checksums = self.directory / "SHA256SUMS"
        checksums.write_text(checksums.read_text() * 2)
        next(a for a in self.release["assets"] if a["name"] == "SHA256SUMS")["size"] = checksums.stat().st_size
        with self.assertRaises(ValueError):
            build_manifest(self.release, 1, self.directory)
        self.release["tag_name"] = "V2-alpine-3.24.2-r1"
        checksums.write_text(f"{self.sha256}  vm_assets.zip\n")
        next(a for a in self.release["assets"] if a["name"] == "SHA256SUMS")["size"] = checksums.stat().st_size
        with self.assertRaises(ValueError):
            build_manifest(self.release, 2, self.directory)

    def test_verifies_submitted_manifest_without_rewriting(self):
        path = self.directory / "v1.json"
        manifest = build_manifest(self.release, 1, self.directory)
        original = json.dumps(manifest, sort_keys=True).encode()
        path.write_bytes(original)
        verify_manifest(path, self.release, 1, self.directory)
        self.assertEqual(path.read_bytes(), original)

    def test_rejects_stale_or_tampered_manifest_fields(self):
        path = self.directory / "v1.json"
        manifest = build_manifest(self.release, 1, self.directory)
        for field, value in (("schemaVersion", True), ("assetVersion", 2),
                             ("size", float(manifest["size"])), ("size", 1),
                             ("sha256", "0" * 64), ("tagName", "V1-alpine-3.24.1-r1")):
            with self.subTest(field=field, value=value):
                path.write_text(json.dumps(dict(manifest, **{field: value})))
                original = path.read_bytes()
                with self.assertRaisesRegex(ValueError, field):
                    verify_manifest(path, self.release, 1, self.directory)
                self.assertEqual(path.read_bytes(), original)

    def test_rejects_missing_extra_duplicate_and_non_object_fields(self):
        path = self.directory / "v1.json"
        manifest = build_manifest(self.release, 1, self.directory)
        bodies = [json.dumps(dict(manifest, url="https://example.invalid")),
                  json.dumps({k: v for k, v in manifest.items() if k != "sha256"}),
                  json.dumps(manifest)[:-1] + ', "assetVersion": 1}', "[]"]
        for body in bodies:
            with self.subTest(body=body):
                path.write_text(body)
                with self.assertRaises(ValueError):
                    verify_manifest(path, self.release, 1, self.directory)


if __name__ == "__main__":
    unittest.main()
