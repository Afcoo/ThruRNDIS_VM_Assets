#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later
"""Assemble verified corresponding source for the VM asset distribution."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import io
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.parse
import zipfile
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from common import (
    ComplianceError,
    Package,
    git_commit,
    iso_timestamp,
    load_lock,
    load_policy,
    load_vm_asset_config,
    normalize_license,
    pkginfo_index,
    require_relative_path,
    sha256_file,
    source_date_epoch,
    validate_package_evidence,
    write_json,
    write_text,
)


APORTS_URL = "https://github.com/alpinelinux/aports.git"
MAX_LICENSE_FILE = 8 * 1024 * 1024
MAX_LICENSE_TOTAL = 64 * 1024 * 1024
MAX_LICENSE_COUNT = 10000
_FETCH_IMAGES: dict[str, str] = {}
ALPINE_DISTFILES_URL = "https://distfiles.alpinelinux.org/distfiles"


def parse_arguments() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=root / "config/packages.lock.json")
    parser.add_argument("--policy", type=Path, default=root / "compliance/license-policy.toml")
    parser.add_argument("--build-dir", type=Path, default=root / "build")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repo", type=Path, default=root)
    parser.add_argument("--aports-url", default=APORTS_URL)
    parser.add_argument("--aports-cache", type=Path)
    parser.add_argument("--distfiles-dir", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--skip-archive", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def run_checked(command: Sequence[str], *, cwd: Path | None = None, capture: bool = False) -> str:
    result = subprocess.run(
        list(command),
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else ""
        raise ComplianceError(f"command failed ({' '.join(command)}): {stderr}")
    return result.stdout if capture and result.stdout is not None else ""


def git_archive(repo: Path, destination: Path) -> str:
    commit = git_commit(repo)
    result = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", commit],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ComplianceError(f"cannot archive builder commit {commit}: {result.stderr.decode(errors='replace')}")
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            relative = require_relative_path(member.name, "builder archive entry")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise ComplianceError(f"cannot extract builder source {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read())
                target.chmod(member.mode & 0o777 or 0o644)
            else:
                raise ComplianceError(f"builder archive contains unsupported entry type: {member.name}")
    return commit


def repository_channel(repository: str) -> str:
    parts = [part for part in repository.rstrip("/").split("/") if part]
    candidates = [part for part in parts if part in {"main", "community", "testing"}]
    if len(candidates) != 1:
        raise ComplianceError(f"cannot derive aports repository channel from {repository!r}")
    return candidates[0]


def prepare_aports_cache(path: Path, url: str) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        run_checked(["git", "init", "--bare", str(path)])
        run_checked(["git", "-C", str(path), "remote", "add", "origin", url])
        return
    if not (path / "HEAD").is_file():
        raise ComplianceError(f"aports cache is not a bare Git repository: {path}")
    remotes = run_checked(["git", "-C", str(path), "remote", "get-url", "origin"], capture=True).strip()
    if remotes != url:
        raise ComplianceError(f"aports cache origin differs: {remotes!r} != {url!r}")


def ensure_commits(cache: Path, commits: Iterable[str], offline: bool) -> None:
    unique_commits = sorted(set(commits))
    missing = []
    for commit in unique_commits:
        result = subprocess.run(
            ["git", "-C", str(cache), "cat-file", "-e", f"{commit}^{{commit}}"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            missing.append(commit)
    if missing and offline:
        raise ComplianceError(f"aports commits are absent from offline cache {cache}: {missing}")
    if missing:
        run_checked(["git", "-C", str(cache), "fetch", "--no-tags", "--depth=1", "origin", *missing])
    for commit in unique_commits:
        resolved = run_checked(
            ["git", "-C", str(cache), "rev-parse", f"{commit}^{{commit}}"], capture=True
        ).strip()
        if resolved != commit:
            raise ComplianceError(f"fetched aports commit differs: {resolved} != {commit}")


def ensure_commit(cache: Path, commit: str, offline: bool) -> None:
    """Compatibility helper used by focused recipe preflight tests."""
    ensure_commits(cache, (commit,), offline)


def export_recipe(cache: Path, commit: str, channel: str, origin: str, destination: Path) -> None:
    prefix = f"{channel}/{origin}"
    listing = run_checked(
        ["git", "-C", str(cache), "ls-tree", "-r", commit, "--", prefix], capture=True
    ).splitlines()
    entries = []
    for raw in listing:
        match = re.fullmatch(r"(\d{6}) blob [0-9a-f]{40}\t(.+)", raw)
        if not match:
            raise ComplianceError(f"cannot parse exact aports tree entry: {raw!r}")
        entries.append((match.group(1), match.group(2)))
    if not any(path == f"{prefix}/APKBUILD" for _, path in entries):
        raise ComplianceError(f"aports {commit} has no {prefix}/APKBUILD")
    for mode, raw in entries:
        relative = PurePosixPath(raw)
        if not relative.is_relative_to(PurePosixPath(prefix)):
            raise ComplianceError(f"unexpected aports path outside recipe: {raw}")
        recipe_relative = relative.relative_to(PurePosixPath(prefix))
        target = destination.joinpath(*recipe_relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "-C", str(cache), "show", f"{commit}:{raw}"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise ComplianceError(f"cannot export aports file {commit}:{raw}")
        if mode == "120000":
            try:
                link_target = result.stdout.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ComplianceError(f"aports symlink target is not UTF-8: {raw}") from error
            if not link_target or "\0" in link_target or PurePosixPath(link_target).is_absolute():
                raise ComplianceError(f"aports symlink has an unsafe target: {raw} -> {link_target!r}")
            resolved = posixpath.normpath(posixpath.join(recipe_relative.parent.as_posix(), link_target))
            if resolved == ".." or resolved.startswith("../"):
                raise ComplianceError(f"aports symlink escapes its recipe: {raw} -> {link_target!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(link_target)
            continue
        if mode not in {"100644", "100755"}:
            raise ComplianceError(f"aports recipe has unsupported Git mode {mode}: {raw}")
        target.write_bytes(result.stdout)
        target.chmod(0o755 if mode == "100755" else 0o644)
    for path in destination.rglob("*"):
        if not path.is_symlink():
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(destination.resolve())
        except (OSError, RuntimeError, ValueError) as error:
            raise ComplianceError(f"aports symlink target is missing or escapes recipe: {path}") from error


def recipe_checksums(apkbuild: Path) -> tuple[str, dict[str, str]]:
    text = apkbuild.read_text(encoding="utf-8")
    for variable, algorithm, length in (
        ("sha512sums", "sha512", 128),
        ("sha256sums", "sha256", 64),
        ("md5sums", "md5", 32),
    ):
        match = re.search(rf"(?ms)^\s*{variable}=(?:\$)?([\"'])(.*?)\1\s*$", text)
        if not match:
            continue
        result: dict[str, str] = {}
        for raw in match.group(2).splitlines():
            raw = raw.strip()
            if not raw:
                continue
            fields = raw.split(None, 1)
            if len(fields) != 2 or not re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", fields[0]):
                raise ComplianceError(f"cannot parse {variable} row in {apkbuild}: {raw!r}")
            filename = fields[1].lstrip("* ")
            require_relative_path(filename, f"{variable} filename")
            if "/" in filename:
                raise ComplianceError(f"distfile checksum name contains a directory: {filename!r}")
            if filename in result:
                raise ComplianceError(f"duplicate checksum filename in {apkbuild}: {filename}")
            result[filename] = fields[0].lower()
        if not result:
            raise ComplianceError(f"empty {variable} in {apkbuild}")
        return algorithm, result
    raise ComplianceError(f"{apkbuild} has no literal sha512sums/sha256sums/md5sums block")


def hash_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_fetch_image(docker: str, alpine_version: str) -> str:
    cached = _FETCH_IMAGES.get(alpine_version)
    if cached is not None:
        return cached
    dockerfile = f"""
FROM alpine:{alpine_version}
RUN apk add --no-cache alpine-sdk && adduser -D sourcebuilder
""".lstrip()
    result = subprocess.run(
        [docker, "build", "--pull", "--quiet", "-"],
        input=dockerfile,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ComplianceError(f"cannot build one-time Alpine source fetcher: {result.stderr.strip()}")
    image = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if not image:
        raise ComplianceError("Docker did not return the one-time source fetcher image ID")
    _FETCH_IMAGES[alpine_version] = image
    return image


def cleanup_fetch_images() -> None:
    docker = shutil.which("docker")
    if docker is None:
        return
    for image in set(_FETCH_IMAGES.values()):
        subprocess.run(
            [docker, "image", "rm", "--force", image],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    _FETCH_IMAGES.clear()


def fetch_recipe_sources(recipe: Path, distfiles: Path, alpine_version: str, architecture: str) -> None:
    docker = shutil.which("docker")
    if docker is None:
        raise ComplianceError(
            f"missing distfiles for {recipe}; install Docker or pre-populate --distfiles-dir and use --offline"
        )
    distfiles.mkdir(parents=True, exist_ok=True)
    fetch_image = source_fetch_image(docker, alpine_version)
    original_mode = distfiles.stat().st_mode & 0o777
    distfiles.chmod(0o777)
    script = """
set -eu
cp -a /recipe /work
chown -R sourcebuilder:sourcebuilder /work
su sourcebuilder -c "cd /work && CARCH='$CARCH' SRCDEST=/distfiles abuild fetch"
find /distfiles -type f -exec chmod 0644 {} +
""".strip()
    try:
        run_checked(
            [
                docker,
                "run",
                "--rm",
                "--network=bridge",
                "-e",
                f"CARCH={architecture}",
                "-v",
                f"{recipe.resolve()}:/recipe:ro",
                "-v",
                f"{distfiles.resolve()}:/distfiles",
                fetch_image,
                "/bin/sh",
                "-ec",
                script,
            ]
        )
    finally:
        distfiles.chmod(original_mode)


def fetch_alpine_distfile(
    cache: Path,
    filename: str,
    branch: str,
    algorithm: str,
    expected_digest: str,
) -> str | None:
    """Fetch an immutable, checksummed copy from Alpine's distfile archive.

    Alpine keeps source files whose original upstream URL has disappeared.
    A mirror miss falls back to the exact APKBUILD URL through ``abuild
    fetch``; a mirror hit with the wrong digest fails closed.
    """

    if not re.fullmatch(r"v[0-9]+\.[0-9]+", branch):
        raise ComplianceError(f"invalid Alpine distfiles branch: {branch!r}")
    curl = shutil.which("curl")
    if curl is None:
        return None
    cache.mkdir(parents=True, exist_ok=True)
    encoded = urllib.parse.quote(filename, safe="")
    url = f"{ALPINE_DISTFILES_URL}/{branch}/{encoded}"
    destination = cache / filename
    temporary = cache / f".{filename}.alpine-download"
    if temporary.exists():
        temporary.unlink()
    result = subprocess.run(
        [
            curl,
            "-fsSL",
            "--retry",
            "3",
            "--retry-all-errors",
            "--connect-timeout",
            "30",
            "--max-time",
            "900",
            "--output",
            str(temporary),
            url,
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        if temporary.exists():
            temporary.unlink()
        return None
    actual = hash_file(temporary, algorithm)
    if actual != expected_digest:
        temporary.unlink()
        raise ComplianceError(
            f"Alpine distfile mirror checksum mismatch for {filename}: "
            f"{actual} != {expected_digest}"
        )
    temporary.replace(destination)
    return url


def collect_distfiles(
    recipe: Path,
    destination: Path,
    cache: Path,
    alpine_branch: str,
    alpine_version: str,
    architecture: str,
    offline: bool,
) -> list[dict[str, Any]]:
    algorithm, expected = recipe_checksums(recipe / "APKBUILD")

    def missing_remote() -> list[str]:
        result = []
        for filename, digest in expected.items():
            local = recipe / filename
            candidate = local if local.is_file() else cache / filename
            if not candidate.is_file():
                result.append(filename)
                continue
            actual = hash_file(candidate, algorithm)
            if actual != digest:
                raise ComplianceError(f"{candidate}: {algorithm} mismatch: {actual} != {digest}")
        return result

    retrieval_urls: dict[str, str] = {}
    missing = missing_remote()
    if missing:
        if offline:
            raise ComplianceError(f"offline source cache lacks {missing} for {recipe}")
        for filename in missing:
            mirror_url = fetch_alpine_distfile(
                cache, filename, alpine_branch, algorithm, expected[filename]
            )
            if mirror_url is not None:
                retrieval_urls[filename] = mirror_url
        missing = missing_remote()
        if missing:
            fetch_recipe_sources(recipe, cache, alpine_version, architecture)
            for filename in missing:
                retrieval_urls[filename] = "APKBUILD source URL via abuild fetch"
            missing = missing_remote()
        if missing:
            raise ComplianceError(f"source fetch did not produce {missing} for {recipe}")

    destination.mkdir(parents=True, exist_ok=True)
    rows = []
    for filename, digest in sorted(expected.items()):
        local = recipe / filename
        if local.is_file():
            # Local patches/configuration are already present in the recipe;
            # record their recipe-relative location instead of duplicating them.
            rows.append({"name": filename, "kind": "aports-local", algorithm: digest})
            continue
        source = cache / filename
        target = destination / filename
        shutil.copyfile(source, target)
        target.chmod(0o644)
        row = {
            "name": filename,
            "kind": "upstream-distfile",
            algorithm: digest,
            "sha256": sha256_file(target),
        }
        if filename in retrieval_urls:
            row["retrievedFrom"] = retrieval_urls[filename]
        rows.append(row)
    return rows


def is_license_path(
    path: PurePosixPath, patterns: Sequence[str], explicit_basenames: Sequence[str] = ()
) -> bool:
    upper_parts = [part.upper() for part in path.parts]
    if "LICENSES" in upper_parts:
        return True
    basename = path.name.upper()
    return basename in {name.upper() for name in explicit_basenames} or any(
        fnmatch.fnmatchcase(basename, pattern.upper()) for pattern in patterns
    )


def safe_license_target(root: Path, source_label: str, member: PurePosixPath) -> Path:
    label = re.sub(r"[^A-Za-z0-9._-]+", "_", source_label)
    relative = require_relative_path(member.as_posix(), "license path")
    return root / f"from-{label}" / Path(*relative.parts)


def extract_licenses_from_tar(
    archive_path: Path,
    target_root: Path,
    patterns: Sequence[str],
    explicit_basenames: Sequence[str],
    budget: list[int],
) -> bool:
    try:
        archive = tarfile.open(archive_path, mode="r:*")
    except (tarfile.TarError, OSError):
        return False
    found = False
    with archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            try:
                relative = require_relative_path(member.name, "distfile archive member")
            except ComplianceError:
                raise
            if not is_license_path(relative, patterns, explicit_basenames):
                continue
            # Some upstream archives carry empty compatibility placeholders
            # next to the authoritative license text (for example zstd's
            # build/LICENSE). Ignore the empty duplicate, then fail below if
            # the origin has no non-empty license/copyright evidence at all.
            if member.size == 0:
                continue
            if member.size > MAX_LICENSE_FILE:
                raise ComplianceError(f"invalid license file size in {archive_path}: {member.name} ({member.size})")
            budget[0] += member.size
            budget[1] += 1
            if budget[0] > MAX_LICENSE_TOTAL or budget[1] > MAX_LICENSE_COUNT:
                raise ComplianceError(f"license evidence limit exceeded while reading {archive_path}")
            source = archive.extractfile(member)
            if source is None:
                raise ComplianceError(f"cannot read license file {member.name} from {archive_path}")
            target = safe_license_target(target_root, archive_path.name, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            data = source.read()
            if target.exists() and target.read_bytes() != data:
                raise ComplianceError(f"archive has conflicting duplicate license path: {archive_path}:{member.name}")
            target.write_bytes(data)
            target.chmod(0o644)
            found = True
    return found


def extract_licenses_from_zip(
    archive_path: Path,
    target_root: Path,
    patterns: Sequence[str],
    explicit_basenames: Sequence[str],
    budget: list[int],
) -> bool:
    try:
        archive = zipfile.ZipFile(archive_path)
    except (zipfile.BadZipFile, OSError):
        return False
    found = False
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            relative = require_relative_path(info.filename, "distfile ZIP member")
            if not is_license_path(relative, patterns, explicit_basenames):
                continue
            if info.file_size == 0:
                continue
            if info.file_size > MAX_LICENSE_FILE:
                raise ComplianceError(f"invalid license file size in {archive_path}: {info.filename}")
            budget[0] += info.file_size
            budget[1] += 1
            if budget[0] > MAX_LICENSE_TOTAL or budget[1] > MAX_LICENSE_COUNT:
                raise ComplianceError(f"license evidence limit exceeded while reading {archive_path}")
            target = safe_license_target(target_root, archive_path.name, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            data = archive.read(info)
            if target.exists() and target.read_bytes() != data:
                raise ComplianceError(f"ZIP has conflicting duplicate license path: {archive_path}:{info.filename}")
            target.write_bytes(data)
            target.chmod(0o644)
            found = True
    return found


def collect_license_evidence(
    origin: str,
    recipe: Path,
    distfiles: Path,
    destination: Path,
    patterns: Sequence[str],
    explicit_basenames: Sequence[str],
) -> list[str]:
    destination.mkdir(parents=True, exist_ok=True)
    budget = [0, 0]
    for path in sorted(recipe.rglob("*")):
        if path.is_file() and is_license_path(
            PurePosixPath(path.relative_to(recipe).as_posix()), patterns, explicit_basenames
        ):
            if path.stat().st_size == 0:
                continue
            if path.stat().st_size > MAX_LICENSE_FILE:
                raise ComplianceError(f"invalid aports license file size: {path}")
            target = destination / "from-aports" / path.relative_to(recipe)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            target.chmod(0o644)
            budget[0] += path.stat().st_size
            budget[1] += 1
    for path in sorted(distfiles.glob("*")):
        if not path.is_file():
            continue
        found = extract_licenses_from_tar(path, destination, patterns, explicit_basenames, budget)
        if not found:
            found = extract_licenses_from_zip(path, destination, patterns, explicit_basenames, budget)
        if not found and is_license_path(PurePosixPath(path.name), patterns, explicit_basenames):
            if path.stat().st_size == 0:
                continue
            if path.stat().st_size > MAX_LICENSE_FILE:
                raise ComplianceError(f"invalid raw license distfile size: {path}")
            target = destination / f"from-{path.name}" / path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            target.chmod(0o644)
            budget[0] += path.stat().st_size
            budget[1] += 1
    files = [path.relative_to(destination.parent.parent).as_posix() for path in sorted(destination.rglob("*")) if path.is_file()]
    if not files:
        raise ComplianceError(f"no copyright/license/notice file found for source origin {origin}")
    return files


def copy_package_evidence(
    packages: Sequence[Package], metadata_dir: Path, archives: Mapping[str, Path], destination: Path
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    expected_names = {package.name for package in packages}
    if set(archives) != expected_names:
        raise ComplianceError("validated APK evidence set differs from runtime package set")
    metadata = pkginfo_index(metadata_dir)
    if set(metadata) != expected_names:
        raise ComplianceError("validated .PKGINFO set differs from runtime package set")
    for package in sorted(packages, key=lambda item: item.name):
        metadata_path, _ = metadata[package.name]
        target = destination / f"{package.filename}.PKGINFO"
        shutil.copyfile(metadata_path, target)
        target.chmod(0o644)
        write_text(destination / f"{package.filename}.sha256", f"{package.sha256}  {package.filename}\n")


def make_building(lock: Mapping[str, Any], commit: str, packages: Sequence[Package]) -> str:
    alpine = lock["alpine"]
    return "\n".join(
        (
            "# Reconstructing the VM Assets",
            "",
            f"Builder commit: `{commit}`",
            f"Alpine: `{alpine['version']}` / `{alpine['arch']}`",
            "",
            "This archive contains every source file distributed for the VM asset",
            "release, including exact aports recipes and verified upstream distfiles.",
            "No network access is needed to inspect or verify these sources.",
            "",
            "## Recompile the corresponding source",
            "",
            "Prepare an Alpine build environment for",
            f"`{alpine['arch']}` with the build dependencies declared by each included",
            "`APKBUILD` already installed. Point `SRCDEST` at the matching directory below",
            "`distfiles/` and run `abuild -r` from each exact recipe. This recompiles the",
            "runtime packages, BusyBox, and `linux-lts` from the provided source, patches,",
            "and configuration. Locally rebuilt APKs need not be byte-for-byte or",
            "signature-identical to Alpine's official APKs and must not be placed into the",
            "locked asset builder cache as substitutes.",
            "",
            "## Reassemble the exact published VM assets offline",
            "",
            "Separately pre-provision the official Alpine ISO at",
            f"`build/cache/iso/{PurePosixPath(str(alpine['isoUrl'])).name}` and every official",
            "runtime APK at `build/cache/apks/<locked file name>`. Every file must match",
            "the SHA-256 recorded in `config/packages.lock.json`; the builder rejects local",
            "recompilations or any other mismatch. Then run:",
            "",
            "```sh",
            "cd builder",
            "./script/make_vm_assets --config config/alpine.env --lock config/packages.lock.json --output build --offline",
            "```",
            "",
            "The exact published kernel image and selected modules are reassembled from",
            "the locked ISO's `boot/vmlinuz-lts` and `boot/modloop-lts`. A local",
            "`linux-lts` recompilation demonstrates source buildability but is not consumed",
            "by this exact-binary reassembly path.",
            "",
            "The checked-in lock, original `.PKGINFO` records, APK digests, source",
            "checksums, kernel and BusyBox recipe configuration, and `SOURCE_MANIFEST.json`",
            "are the comparison points for reconstruction. Build-tool packages are not",
            "part of the distributed VM image and must be provisioned separately.",
            "",
            "Included origins: " + ", ".join(sorted({package.origin for package in packages})),
            "",
        )
    )


def source_inventory(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == "SOURCE_MANIFEST.json":
            continue
        if path.is_symlink():
            target = os.readlink(path)
            if not target or PurePosixPath(target).is_absolute():
                raise ComplianceError(f"unsafe source-bundle symlink: {relative} -> {target!r}")
            resolved = posixpath.normpath(posixpath.join(PurePosixPath(relative).parent.as_posix(), target))
            if resolved == ".." or resolved.startswith("../"):
                raise ComplianceError(f"source-bundle symlink escapes root: {relative} -> {target!r}")
            rows.append({"path": relative, "type": "symlink", "target": target})
        elif path.is_file():
            rows.append(
                {
                    "path": relative,
                    "type": "file",
                    "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
                    "sha256": sha256_file(path),
                    "size": path.stat().st_size,
                }
            )
    return rows


def deterministic_source_archive(staging: Path, output: Path, epoch: int) -> None:
    tar = shutil.which("tar")
    zstd = shutil.which("zstd")
    if tar is None or zstd is None:
        raise ComplianceError("creating vm_assets-sources.tar.zst requires GNU tar and zstd")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists():
        temporary.unlink()
    run_checked(
        [
            tar,
            "--sort=name",
            f"--mtime=@{epoch}",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--format=gnu",
            "--transform=s,^source-bundle,vm_assets-sources,",
            "--zstd",
            "-cf",
            str(temporary),
            "-C",
            str(staging.parent),
            staging.name,
        ]
    )
    temporary.replace(output)


def run(arguments: argparse.Namespace) -> None:
    repo = arguments.repo.resolve()
    build_dir = arguments.build_dir.resolve()
    output = (arguments.output or build_dir / "release/vm_assets-sources.tar.zst").resolve()
    staging = build_dir / "source-bundle"
    aports_cache = (arguments.aports_cache or build_dir / "cache/aports.git").resolve()
    distfile_cache = (arguments.distfiles_dir or build_dir / "cache/distfiles").resolve()
    lock, packages = load_lock(arguments.lock.resolve())
    policy = load_policy(arguments.policy.resolve())
    for package in packages:
        normalize_license(package.license_expression, policy)
    runtime_packages = [package for package in packages if package.role == "runtime"]
    archives = validate_package_evidence(runtime_packages, build_dir / "provenance/packages", build_dir / "cache/apks")

    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    commit = git_archive(repo, staging / "builder")
    asset_config = load_vm_asset_config(staging / "builder/config/vm-assets.json")
    epoch = source_date_epoch(repo)
    copy_package_evidence(runtime_packages, build_dir / "provenance/packages", archives, staging / "packages")

    prepare_aports_cache(aports_cache, arguments.aports_url)
    patterns = policy.get("source_license_patterns", [])
    if not isinstance(patterns, list) or not all(isinstance(pattern, str) for pattern in patterns):
        raise ComplianceError("source_license_patterns policy must be an array of strings")
    origin_license_files = policy.get("origin_license_files", {})
    if not isinstance(origin_license_files, dict) or not all(
        isinstance(origin, str)
        and isinstance(names, list)
        and all(isinstance(name, str) and "/" not in name for name in names)
        for origin, names in origin_license_files.items()
    ):
        raise ComplianceError("origin_license_files policy must map origins to basename arrays")
    recipe_keys: dict[str, tuple[str, str]] = {}
    groups: dict[tuple[str, str, str], list[Package]] = defaultdict(list)
    for package in packages:
        channel = "main" if package.role == "kernel" else repository_channel(package.repository)
        key = (package.aports_commit, channel, package.origin)
        groups[key].append(package)
        previous = recipe_keys.get(package.origin)
        current = (package.aports_commit, channel)
        if previous is not None and previous != current:
            raise ComplianceError(f"origin {package.origin} maps to more than one exact aports recipe")
        recipe_keys[package.origin] = current

    ensure_commits(aports_cache, (key[0] for key in groups), arguments.offline)

    source_rows = []
    for (aports_commit, channel, origin), origin_packages in sorted(groups.items()):
        recipe = staging / "aports" / aports_commit / channel / origin
        export_recipe(aports_cache, aports_commit, channel, origin, recipe)
        origin_distfiles = staging / "distfiles" / origin
        rows = collect_distfiles(
            recipe,
            origin_distfiles,
            distfile_cache / origin,
            str(lock["alpine"]["branch"]),
            str(lock["alpine"]["version"]),
            str(lock["alpine"]["arch"]),
            arguments.offline,
        )
        licenses = collect_license_evidence(
            origin,
            recipe,
            origin_distfiles,
            staging / "licenses" / origin,
            patterns,
            origin_license_files.get(origin, []),
        )
        source_rows.append(
            {
                "origin": origin,
                "packages": sorted(package.name for package in origin_packages),
                "aportsCommit": aports_commit,
                "repository": channel,
                "distfiles": rows,
                "licenseFiles": licenses,
            }
        )

    required_origins = set(policy.get("required_source_origins", []))
    actual_origins = {row["origin"] for row in source_rows}
    if not required_origins.issubset(actual_origins):
        raise ComplianceError(f"source bundle lacks required origins: {sorted(required_origins - actual_origins)}")
    write_text(staging / "BUILDING.md", make_building(lock, commit, packages))
    write_json(staging / "SOURCES.json", {"schemaVersion": 1, "builderCommit": commit, "sources": source_rows})
    files = source_inventory(staging)
    source_manifest = {
        "schemaVersion": 1,
        "assetVersion": asset_config["assetVersion"],
        "created": iso_timestamp(epoch),
        "builderCommit": commit,
        "alpine": lock["alpine"],
        "files": files,
    }
    write_json(staging / "SOURCE_MANIFEST.json", source_manifest)

    if not arguments.skip_archive:
        deterministic_source_archive(staging, output, epoch)
        write_json(
            Path(str(output) + ".manifest.json"),
            {
                "schemaVersion": 1,
                "archive": output.name,
                "sha256": sha256_file(output),
                "size": output.stat().st_size,
                "sourceManifestSha256": sha256_file(staging / "SOURCE_MANIFEST.json"),
            },
        )
        print(f"Wrote {output} ({sha256_file(output)})")
    print(f"Prepared corresponding source at {staging}")


def main() -> int:
    try:
        run(parse_arguments())
    except (ComplianceError, OSError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"source bundle failed: {error}", file=sys.stderr)
        return 1
    finally:
        cleanup_fetch_images()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
