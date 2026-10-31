#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

"""Choose verification from Git changes and check changed feeds against Releases."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

from download_manifest import select_release, verify_manifest

MANIFEST_PATH = re.compile(r"releases/v([1-9][0-9]*)\.json")


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args])


def commit(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("Expected a full commit SHA in the event payload")
    return value


def verification_plan(event_name: str, event: dict) -> dict:
    # Manual runs and newly created branches retain full verification. There is
    # no previous push tree for a new branch; do not guess a manifest-only diff.
    full = {"build_required": True, "manifests": []}
    if event_name == "workflow_dispatch":
        return full
    if event_name == "pull_request":
        base = commit(event["pull_request"]["base"]["sha"])
        head = commit(event["pull_request"]["head"]["sha"])
        refs = [f"{base}...{head}"]
    elif event_name == "push":
        base, head = commit(event["before"]), commit(event["after"])
        if head == "0" * 40:
            raise ValueError("Cannot verify a deleted ref")
        if base == "0" * 40:
            return full
        refs = [base, head]
    else:
        raise ValueError(f"Unsupported verification event: {event_name}")

    # NUL separators preserve arbitrary filenames. Disable rename detection so
    # moving an existing feed is treated as deletion, never as a new channel.
    changes = git("diff", "--no-ext-diff", "--no-renames", "--name-status", "-z", *refs, "--")
    if not changes:
        return full
    fields = changes.decode("utf-8").split("\0")
    if fields.pop() != "" or len(fields) % 2:
        raise ValueError("Malformed Git change list")
    manifests = []
    build_required = False
    for status, path in zip(fields[::2], fields[1::2]):
        if not MANIFEST_PATH.fullmatch(path):
            build_required = True
            continue
        if status not in ("A", "M"):
            raise ValueError(f"Download manifests may only be added or modified: {status} {path}")
        entry = git("ls-tree", head, "--", path).decode("utf-8")
        if not entry.startswith("100644 blob "):
            raise ValueError(f"Download manifest must be a regular non-executable file: {path}")
        manifests.append(path)
    return {"build_required": build_required, "manifests": sorted(manifests)}


def verify_downloads(paths: list[str], repository: str) -> None:
    if not paths or any(not MANIFEST_PATH.fullmatch(path) for path in paths):
        raise ValueError("Expected changed releases/v<positive integer>.json paths")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Expected an owner/repository name")
    # Paginate: the newest compatible channel need not be on the first page.
    pages = json.loads(subprocess.check_output([
        "gh", "api", "--paginate", "--slurp", f"repos/{repository}/releases?per_page=100",
    ]))
    releases = [release for page in pages for release in page]
    for name in paths:
        path = Path(name)
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(Path.cwd()):
            raise ValueError(f"Download manifest must be a regular repository file: {path}")
        version = int(MANIFEST_PATH.fullmatch(name)[1])
        release = select_release(releases, version)
        with tempfile.TemporaryDirectory(prefix="verify-manifest-") as directory:
            subprocess.run([
                "gh", "release", "download", release["tag_name"], "--repo", repository,
                "--dir", directory, "--pattern", "vm_assets.zip", "--pattern", "SHA256SUMS",
            ], check=True)
            verify_manifest(path, release, version, Path(directory))
        print(f"Verified {path} against {release['tag_name']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "verify"))
    parser.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "plan":
            plan = verification_plan(os.environ["GITHUB_EVENT_NAME"],
                                     json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()))
            args.plan.write_text(json.dumps(plan) + "\n")
            with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
                output.write(f"build_required={str(plan['build_required']).lower()}\n")
                output.write(f"manifest_changed={str(bool(plan['manifests'])).lower()}\n")
            print(json.dumps(plan))
        else:
            plan = json.loads(args.plan.read_text())
            verify_downloads(plan["manifests"], os.environ["GITHUB_REPOSITORY"])
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError,
            zipfile.BadZipFile) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
