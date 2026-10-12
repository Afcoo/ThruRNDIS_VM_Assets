#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

"""Render dependency changes from locked inputs, without resolving dependencies."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


def cell(value: object) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(
        ">", "&gt;"
    ).replace("|", "&#124;").replace("`", "&#96;").replace("\n", " ").replace("\r", " ")


def package_index(lock: dict) -> dict:
    result = {}
    for package in lock["packages"]:
        key = (package["name"], package.get("role", "runtime"))
        if key in result:
            raise ValueError(f"Duplicate locked package: {key}")
        result[key] = package
    return result


def dependency_summary(before: dict | None, after: dict) -> str:
    old_packages = package_index(before) if before is not None else {}
    new_packages = package_index(after)
    lines = ["## Dependency changes", ""]
    old_alpine = before["alpine"]["version"] if before is not None else "—"
    lines += [f"Alpine: {cell(old_alpine)} → {cell(after['alpine']['version'])}", ""]
    for key in sorted(set(old_packages) | set(new_packages)):
        if key[1] == "kernel":
            old = old_packages.get(key, {}).get("version", "—")
            new = new_packages.get(key, {}).get("version", "—")
            lines += [f"**Kernel ({cell(key[0])}): {cell(old)} → {cell(new)}**", ""]
    rows = []
    for key in sorted(set(old_packages) | set(new_packages)):
        old, new = old_packages.get(key), new_packages.get(key)
        if old == new:
            continue
        if old is None:
            change = "Included" if before is None else "Added"
        elif new is None:
            change = "Removed"
        elif old["version"] != new["version"]:
            change = "Version changed"
        else:
            change = "Metadata changed (version unchanged)"
        rows.append("| " + " | ".join(cell(value) for value in (
            key[0], key[1], old["version"] if old else "—",
            new["version"] if new else "—", change,
        )) + " |")
    if rows:
        lines += ["| Package | Role | Previous version | New version | Change |",
                  "| --- | --- | --- | --- | --- |", *rows]
    else:
        lines.append("No package version or package metadata changes.")
    return "\n".join(lines) + "\n"


def select_baseline(releases: list[dict], current_tag: str) -> str | None:
    """Prefer versioned releases; GitHub Latest intentionally points to legacy."""
    published = [release for release in releases
                 if release["tag_name"] != current_tag
                 and release.get("draft") is False
                 and release.get("prerelease") is False]
    versioned = [release for release in published if re.fullmatch(
        r"V[1-9][0-9]*-alpine-[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]*",
        release["tag_name"],
    )]
    candidates = versioned or [release for release in published
                              if release["tag_name"] == "alpine-3.24.1-r2"]
    if not candidates:
        return None
    if any(not release.get("published_at") for release in candidates):
        raise ValueError("Published baseline release is missing published_at")
    return max(candidates, key=lambda release: (
        release["published_at"], release["tag_name"]
    ))["tag_name"]


def render_release_notes(after: dict, before: dict | None, *, baseline: str | None,
                         asset_version: int, commit: str) -> str:
    lines = [f"ThruRNDIS VM assets for the locked Alpine inputs at {commit}.", "",
             f"VM asset version: {asset_version}.", ""]
    if baseline is None:
        lines += ["First release: listing all locked packages; no published baseline exists.", ""]
    else:
        lines += [f"Compared with published release **{cell(baseline)}**.", ""]
    lines += [dependency_summary(before, after),
              "The binary is a multi-license aggregate. Download vm_assets-sources.tar.zst,",
              "THIRD_PARTY_NOTICES.md, and sbom.spdx.json with vm_assets.zip.", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--releases-json", type=Path, required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--asset-version", type=int, required=True)
    args = parser.parse_args()
    releases = json.loads(args.releases_json.read_text(encoding="utf-8"))
    baseline = select_baseline(releases, args.release_tag)
    # Read the published tag, never target_commitish (which may name a moving branch).
    # A missing tag/lock is an error, not an excuse to claim this is a first release.
    before = None
    if baseline is not None:
        before = json.loads(subprocess.check_output(
            ["git", "show", f"refs/tags/{baseline}:config/packages.lock.json"], text=True,
        ))
    print(render_release_notes(
        json.loads(args.lock.read_text(encoding="utf-8")), before,
        baseline=baseline, asset_version=args.asset_version, commit=args.release_commit,
    ), end="")


if __name__ == "__main__":
    main()
