# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "script"))

from select_release_tag import (  # noqa: E402
    SelectionError,
    load_versions,
    select_release_tag,
)


class ReleaseTagTests(unittest.TestCase):
    release_commit = "a" * 40
    other_commit = "b" * 40
    namespace = "V1-alpine-3.24.1-"

    def release(
        self,
        revision: int,
        *,
        draft: bool = False,
        target: str | None = None,
        prerelease: bool = False,
        name: str | None = None,
    ) -> dict[str, object]:
        return {
            "tag_name": name or f"{self.namespace}r{revision}",
            "draft": draft,
            "prerelease": prerelease,
            "target_commitish": target or self.other_commit,
        }

    def tag(
        self,
        revision: int,
        *,
        commit: str | None = None,
        name: str | None = None,
    ) -> dict[str, object]:
        return {
            "name": name or f"{self.namespace}r{revision}",
            "commit": {"sha": commit or self.other_commit},
        }

    def select(
        self,
        releases: list[dict[str, object]],
        tags: list[dict[str, object]],
    ) -> str:
        return select_release_tag(
            1,
            "3.24.1",
            self.release_commit,
            releases,
            tags,
        )

    def test_first_release_uses_revision_one(self) -> None:
        self.assertEqual(self.select([], []), f"{self.namespace}r1")

    def test_next_revision_follows_largest_published_release(self) -> None:
        releases = [self.release(1), self.release(3)]
        tags = [self.tag(1), self.tag(3)]
        self.assertEqual(self.select(releases, tags), f"{self.namespace}r4")

    def test_other_tag_namespaces_do_not_affect_revision(self) -> None:
        releases = [
            {
                **self.release(9),
                "tag_name": "V1-alpine-3.24.0-r9",
            },
            {
                **self.release(8),
                "tag_name": "vm-assets-v1-alpine-3.24.1-r8",
            },
        ]
        tags = [
            {
                **self.tag(9),
                "name": "V1-alpine-3.24.0-r9",
            },
            {
                **self.tag(8),
                "name": "vm-assets-v1-alpine-3.24.1-r8",
            },
        ]
        self.assertEqual(self.select(releases, tags), f"{self.namespace}r1")

    def test_matching_latest_draft_is_reused(self) -> None:
        releases = [
            self.release(1),
            self.release(2, draft=True, target=self.release_commit),
        ]
        tags = [self.tag(1), self.tag(2, commit=self.release_commit)]
        self.assertEqual(self.select(releases, tags), f"{self.namespace}r2")

    def test_draft_for_another_commit_is_rejected(self) -> None:
        releases = [self.release(1, draft=True, target=self.other_commit)]
        tags = [self.tag(1, commit=self.other_commit)]
        with self.assertRaisesRegex(SelectionError, "targets .* not"):
            self.select(releases, tags)

    def test_orphan_release_or_tag_is_rejected(self) -> None:
        with self.subTest("release without tag"), self.assertRaisesRegex(
            SelectionError, "has no repository tag"
        ):
            self.select([self.release(1)], [])
        with self.subTest("tag without release"), self.assertRaisesRegex(
            SelectionError, "has no Release"
        ):
            self.select([], [self.tag(1)])

    def test_malformed_matching_name_is_rejected(self) -> None:
        malformed = f"{self.namespace}r01"
        with self.assertRaisesRegex(SelectionError, "Malformed Release name"):
            self.select([self.release(1, name=malformed)], [])
        with self.assertRaisesRegex(SelectionError, "Malformed tag name"):
            self.select([], [self.tag(1, name=malformed)])

    def test_prerelease_and_ambiguous_drafts_are_rejected(self) -> None:
        with self.subTest("prerelease"), self.assertRaisesRegex(
            SelectionError, "must not be a prerelease"
        ):
            self.select([self.release(1, prerelease=True)], [self.tag(1)])

        releases = [
            self.release(1, draft=True, target=self.release_commit),
            self.release(2, draft=True, target=self.release_commit),
        ]
        tags = [
            self.tag(1, commit=self.release_commit),
            self.tag(2, commit=self.release_commit),
        ]
        with self.subTest("multiple drafts"), self.assertRaisesRegex(
            SelectionError, "Multiple draft Releases"
        ):
            self.select(releases, tags)

    def test_versions_are_read_from_checked_in_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            asset_config = directory / "vm-assets.json"
            alpine_config = directory / "alpine.env"
            asset_config.write_text(json.dumps({"assetVersion": 7}))
            alpine_config.write_text("ALPINE_VERSION='3.25.0'\n")
            self.assertEqual(load_versions(asset_config, alpine_config), (7, "3.25.0"))

            alpine_config.write_text("ALPINE_VERSION=edge\n")
            with self.assertRaisesRegex(SelectionError, "major.minor.patch"):
                load_versions(asset_config, alpine_config)

            asset_config.write_text("[]")
            with self.assertRaisesRegex(SelectionError, "JSON object"):
                load_versions(asset_config, alpine_config)


if __name__ == "__main__":
    unittest.main()
