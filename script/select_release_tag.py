#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

"""Select the deterministic tag for a VM asset Release workflow run."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
from dataclasses import dataclass
from typing import Any


class SelectionError(ValueError):
    """The repository's Release/tag state is unsafe or ambiguous."""


@dataclass(frozen=True)
class ReleaseState:
    name: str
    revision: int
    draft: bool
    target: str


@dataclass(frozen=True)
class TagState:
    name: str
    revision: int
    commit: str


def load_versions(
    asset_config_path: pathlib.Path, alpine_config_path: pathlib.Path
) -> tuple[int, str]:
    try:
        asset_config = json.loads(asset_config_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SelectionError(f"Unable to read {asset_config_path}: {error}") from error
    if not isinstance(asset_config, dict):
        raise SelectionError(f"{asset_config_path} must contain a JSON object")

    asset_version = asset_config.get("assetVersion")
    if (
        isinstance(asset_version, bool)
        or not isinstance(asset_version, int)
        or asset_version < 1
    ):
        raise SelectionError(
            f"{asset_config_path} must contain a positive integer assetVersion"
        )

    try:
        alpine_lines = alpine_config_path.read_text().splitlines()
    except OSError as error:
        raise SelectionError(f"Unable to read {alpine_config_path}: {error}") from error

    alpine_versions: list[str] = []
    for raw_line in alpine_lines:
        line = raw_line.strip()
        if line.startswith("ALPINE_VERSION="):
            value = line.split("=", 1)[1].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            alpine_versions.append(value)

    if len(alpine_versions) != 1:
        raise SelectionError(
            f"{alpine_config_path} must define ALPINE_VERSION exactly once"
        )
    alpine_version = alpine_versions[0]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", alpine_version):
        raise SelectionError(
            f"{alpine_config_path} ALPINE_VERSION must use major.minor.patch"
        )

    return asset_version, alpine_version


def load_json_array(path: pathlib.Path, description: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SelectionError(
            f"Unable to read {description} from {path}: {error}"
        ) from error
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise SelectionError(f"{description} in {path} must be a JSON array of objects")
    return value


def _matching_revision(name: str, namespace: str, description: str) -> int | None:
    if not name.startswith(namespace):
        return None
    match = re.fullmatch(re.escape(namespace) + r"r([1-9][0-9]*)", name)
    if not match:
        raise SelectionError(f"Malformed {description} name in release namespace: {name}")
    return int(match.group(1))


def select_release_tag(
    asset_version: int,
    alpine_version: str,
    release_commit: str,
    releases: list[dict[str, Any]],
    tags: list[dict[str, Any]],
) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", release_commit):
        raise SelectionError("release commit must be a full hexadecimal Git object ID")
    release_commit = release_commit.lower()
    namespace = f"V{asset_version}-alpine-{alpine_version}-"

    releases_by_revision: dict[int, ReleaseState] = {}
    for item in releases:
        name = item.get("tag_name")
        if not isinstance(name, str):
            raise SelectionError("GitHub Release data contains a non-string tag_name")
        revision = _matching_revision(name, namespace, "Release")
        if revision is None:
            continue
        if revision in releases_by_revision:
            raise SelectionError(f"Duplicate GitHub Release revision: r{revision}")

        draft = item.get("draft")
        prerelease = item.get("prerelease")
        target = item.get("target_commitish")
        if not isinstance(draft, bool) or not isinstance(prerelease, bool):
            raise SelectionError(f"Release {name} has invalid draft/prerelease state")
        if prerelease:
            raise SelectionError(f"Release {name} must not be a prerelease")
        if not isinstance(target, str) or not target:
            raise SelectionError(f"Release {name} has no target commit")
        releases_by_revision[revision] = ReleaseState(
            name=name,
            revision=revision,
            draft=draft,
            target=target,
        )

    tags_by_revision: dict[int, TagState] = {}
    for item in tags:
        name = item.get("name")
        if not isinstance(name, str):
            raise SelectionError("GitHub tag data contains a non-string name")
        revision = _matching_revision(name, namespace, "tag")
        if revision is None:
            continue
        if revision in tags_by_revision:
            raise SelectionError(f"Duplicate repository tag revision: r{revision}")

        commit_data = item.get("commit")
        commit = commit_data.get("sha") if isinstance(commit_data, dict) else None
        if not isinstance(commit, str) or not commit:
            raise SelectionError(f"Repository tag {name} has no commit")
        tags_by_revision[revision] = TagState(
            name=name,
            revision=revision,
            commit=commit.lower(),
        )

    release_revisions = set(releases_by_revision)
    tag_revisions = set(tags_by_revision)
    if release_revisions != tag_revisions:
        problems: list[str] = []
        for revision in sorted(tag_revisions - release_revisions):
            problems.append(f"tag {tags_by_revision[revision].name} has no Release")
        for revision in sorted(release_revisions - tag_revisions):
            problems.append(
                f"Release {releases_by_revision[revision].name} has no repository tag"
            )
        raise SelectionError("Inconsistent Release/tag state: " + "; ".join(problems))

    if not release_revisions:
        return f"{namespace}r1"

    maximum_revision = max(release_revisions)
    drafts = [state for state in releases_by_revision.values() if state.draft]
    if drafts:
        if len(drafts) != 1:
            names = ", ".join(sorted(state.name for state in drafts))
            raise SelectionError(f"Multiple draft Releases exist in namespace: {names}")
        draft = drafts[0]
        if draft.revision != maximum_revision:
            raise SelectionError(
                f"Draft Release {draft.name} is not the latest revision in its namespace"
            )
        if draft.target != release_commit:
            raise SelectionError(
                f"Draft Release {draft.name} targets {draft.target}, not {release_commit}"
            )
        tag = tags_by_revision[draft.revision]
        if tag.commit != release_commit:
            raise SelectionError(
                f"Repository tag {tag.name} points to {tag.commit}, not {release_commit}"
            )
        return draft.name

    return f"{namespace}r{maximum_revision + 1}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-config", type=pathlib.Path, required=True)
    parser.add_argument("--alpine-config", type=pathlib.Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--releases-json", type=pathlib.Path, required=True)
    parser.add_argument("--tags-json", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        asset_version, alpine_version = load_versions(
            args.asset_config, args.alpine_config
        )
        release_tag = select_release_tag(
            asset_version,
            alpine_version,
            args.release_commit,
            load_json_array(args.releases_json, "GitHub Releases"),
            load_json_array(args.tags_json, "repository tags"),
        )
    except SelectionError as error:
        raise SystemExit(f"Release tag selection failed: {error}") from error

    print(f"RELEASE_TAG={release_tag}")
    print(f"VM_ASSET_VERSION={asset_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
