#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

"""Generate the static app download manifest from a published, verified Release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path

REQUIRED_ASSETS = {
    "vm_assets.zip", "vm_assets-sources.tar.zst", "sbom.spdx.json",
    "THIRD_PARTY_NOTICES.md", "SHA256SUMS",
}


def select_release(releases: list[dict], asset_version: int) -> dict:
    if type(asset_version) is not int or asset_version < 1:
        raise ValueError("assetVersion must be a positive integer")
    candidates = [
        release for release in releases
        if release.get("draft") is False and release.get("prerelease") is False
        and release.get("tag_name", "").startswith(f"V{asset_version}-")
    ]
    if not candidates:
        raise ValueError(f"No published V{asset_version} Release")
    release = max(candidates, key=lambda value: (
        datetime.fromisoformat(value["created_at"].replace("Z", "+00:00")), value["id"]
    ))
    if not re.fullmatch(rf"V{asset_version}-[A-Za-z0-9][A-Za-z0-9._-]*", release["tag_name"]):
        raise ValueError("Release tag is not a safe URL component")
    assets = release["assets"]
    if len(assets) != len(REQUIRED_ASSETS) or {item["name"] for item in assets} != REQUIRED_ASSETS:
        raise ValueError("Published Release must have exactly the five distribution assets")
    if any(type(item["size"]) is not int or item["size"] <= 0 for item in assets):
        raise ValueError("Published Release contains an empty or invalid asset")
    return release


def build_manifest(release: dict, asset_version: int, directory: Path) -> dict:
    # Also validate direct callers; an incomplete newest release must not fall back to an older one.
    select_release([release], asset_version)
    assets = {item["name"]: item for item in release["assets"]}
    archive_path = directory / "vm_assets.zip"
    checksums_path = directory / "SHA256SUMS"
    for path in (archive_path, checksums_path):
        if path.stat().st_size != assets[path.name]["size"]:
            raise ValueError(f"Release size mismatch: {path.name}")
    digest = hashlib.sha256()
    with archive_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    sha256 = digest.hexdigest()
    hashes = []
    for line in checksums_path.read_text().splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([a-fA-F0-9]{64})\s+\*?(\S+)", line)
        if match is None:
            raise ValueError("Malformed SHA256SUMS")
        if match[2] in ("vm_assets.zip", "./vm_assets.zip"):
            hashes.append(match[1].lower())
    if hashes != [sha256]:
        raise ValueError("SHA256SUMS must contain exactly one matching archive hash")
    github_digest = assets["vm_assets.zip"].get("digest")
    if github_digest is not None and github_digest != f"sha256:{sha256}":
        raise ValueError("GitHub archive digest mismatch")
    with zipfile.ZipFile(archive_path) as archive:
        version = json.loads(archive.read("vm_assets/manifest.json"))["assetVersion"]
    if type(version) is not int or version != asset_version:
        raise ValueError("Archive assetVersion does not match its download channel")
    return {
        "schemaVersion": 1,
        "assetVersion": asset_version,
        "tagName": release["tag_name"],
        "size": archive_path.stat().st_size,
        "sha256": sha256,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("select", "write"))
    parser.add_argument("--releases-json", type=Path, required=True)
    parser.add_argument("--asset-version", type=int, required=True)
    parser.add_argument("--download-dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        release = select_release(json.loads(args.releases_json.read_text()), args.asset_version)
        if args.command == "select":
            print(release["tag_name"])
            return
        if args.download_dir is None or args.output is None:
            parser.error("write requires --download-dir and --output")
        manifest = build_manifest(release, args.asset_version, args.download_dir)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"Wrote {args.output}: {release['tag_name']}")
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
