#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later
"""Fail-closed verification for VM assets and their corresponding source."""

from __future__ import annotations

import argparse
import hashlib
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from common import (
    CpioEntry,
    ComplianceError,
    Package,
    canonical_json,
    check_initramfs_content,
    checksum_manifest,
    load_file_map,
    load_json,
    load_lock,
    load_policy,
    load_vm_asset_config,
    normalize_license,
    parse_pkginfo,
    read_newc,
    require_relative_path,
    sha256_file,
    validate_package_evidence,
    verify_file_map,
)
from build_compliance import (
    aggregate_license_expression,
    find_iso,
    make_notices,
    make_source_notice,
    validate_kernel_provenance,
    validate_packages_provenance,
    validate_asset_allowlist,
)
from source_bundle import hash_file, recipe_checksums, repository_channel


def parse_arguments() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=root / "config/packages.lock.json")
    parser.add_argument("--policy", type=Path, default=root / "compliance/license-policy.toml")
    parser.add_argument("--build-dir", type=Path, default=root / "build")
    parser.add_argument("--asset-dir", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--source-bundle", type=Path)
    parser.add_argument("--repo", type=Path, default=root)
    return parser.parse_args()


def unique_asset(asset_dir: Path, pattern: str) -> Path:
    matches = sorted(path for path in asset_dir.glob(pattern) if path.is_file())
    if len(matches) != 1:
        raise ComplianceError(f"expected one asset matching {pattern}; found {matches}")
    if matches[0].stat().st_size == 0:
        raise ComplianceError(f"empty asset: {matches[0]}")
    return matches[0]


def verify_mdns_payload(entries: Sequence[CpioEntry], repo: Path) -> None:
    """Require the reviewed static service, its digest and usb0-only config."""
    service_path = "etc/avahi/services/thrurndis.service"
    services = {
        entry.path for entry in entries
        if entry.path.startswith("etc/avahi/services/")
    }
    if services != {service_path}:
        raise ComplianceError(f"DNS-SD service allowlist differs: {sorted(services)}")
    by_path = {entry.path: entry for entry in entries}
    service = (repo / "script/thrurndis.service").read_bytes()
    expected = {
        service_path: service,
        "etc/avahi/avahi-daemon.conf": (repo / "script/avahi-daemon.conf").read_bytes(),
        "usr/local/libexec/thrurndis/mdns-service.sha256":
            (hashlib.sha256(service).hexdigest() + "\n").encode(),
    }
    for path, content in expected.items():
        entry = by_path.get(path)
        if entry is None or entry.kind != "file" or entry.data != content:
            raise ComplianceError(f"DNS-SD payload differs from repository: {path}")
        if stat.S_IMODE(entry.mode) != 0o644:
            raise ComplianceError(f"DNS-SD payload mode differs: {path}")


def verify_checksum_file(asset_dir: Path) -> None:
    checksum_path = asset_dir / "SHA256SUMS"
    try:
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ComplianceError(f"cannot read {checksum_path}: {error}") from error
    declared: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ComplianceError(f"invalid SHA256SUMS line: {line!r}")
        digest, raw_path = match.groups()
        relative = str(require_relative_path(raw_path, "SHA256SUMS path"))
        if relative in declared:
            raise ComplianceError(f"duplicate SHA256SUMS path: {relative}")
        declared[relative] = digest
    actual = {relative: digest for digest, relative in checksum_manifest(asset_dir, exclude=("SHA256SUMS",))}
    if declared != actual:
        missing = sorted(set(actual) - set(declared))
        extra = sorted(set(declared) - set(actual))
        mismatched = sorted(path for path in set(actual) & set(declared) if actual[path] != declared[path])
        raise ComplianceError(f"SHA256SUMS differs from assets; missing={missing}, extra={extra}, mismatched={mismatched}")


def verify_manifest(
    asset_dir: Path,
    lock: dict[str, Any],
    packages: Sequence[Package],
    provenance_dir: Path,
    licenses: Mapping[str, str],
    asset_version: int,
) -> None:
    manifest_path = asset_dir / "manifest.json"
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        raise ComplianceError(f"{manifest_path}: unsupported schema")
    if manifest.get("assetVersion") != asset_version:
        raise ComplianceError(f"{manifest_path}: assetVersion differs from config")
    if manifest.get("alpine") != lock["alpine"]:
        raise ComplianceError(f"{manifest_path}: Alpine metadata differs from lock")
    builder = manifest.get("builder")
    if not isinstance(builder, dict) or not re.fullmatch(r"[0-9a-f]{40}", str(builder.get("commit", ""))):
        raise ComplianceError(f"{manifest_path}: invalid builder commit")
    rows = manifest.get("packages")
    if not isinstance(rows, list):
        raise ComplianceError(f"{manifest_path}: packages must be an array")
    manifest_packages = {row.get("name"): row for row in rows if isinstance(row, dict)}
    if set(manifest_packages) != {package.name for package in packages}:
        raise ComplianceError(f"{manifest_path}: package set differs from lock")
    for package in packages:
        row = manifest_packages[package.name]
        expected = {
            "version": package.version,
            "origin": package.origin,
            "role": package.role,
            "sha256": package.sha256,
            "aportsCommit": package.aports_commit,
        }
        for key, value in expected.items():
            if row.get(key) != value:
                raise ComplianceError(f"{manifest_path}: {package.name}.{key} differs from lock")
        if row.get("license") != licenses[package.name]:
            raise ComplianceError(f"{manifest_path}: {package.name}.license differs from normalized lock")

    artifact_rows = manifest.get("artifacts")
    if not isinstance(artifact_rows, list):
        raise ComplianceError(f"{manifest_path}: artifacts must be an array")
    declared = {}
    for row in artifact_rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ComplianceError(f"{manifest_path}: malformed artifact")
        relative = str(require_relative_path(row["path"], "manifest artifact"))
        path = asset_dir / relative
        if not path.is_file():
            raise ComplianceError(f"{manifest_path}: missing declared artifact {relative}")
        if row.get("sha256") != sha256_file(path) or row.get("size") != path.stat().st_size:
            raise ComplianceError(f"{manifest_path}: artifact digest/size differs for {relative}")
        declared[relative] = row
    actual = {
        relative
        for _, relative in checksum_manifest(asset_dir, exclude=("manifest.json", "SHA256SUMS"))
    }
    if set(declared) != actual:
        raise ComplianceError(f"{manifest_path}: artifact inventory differs from asset directory")

    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict):
        raise ComplianceError(f"{manifest_path}: provenance is missing")
    for filename in ("packages.json", "kernel.json", "file-map.json"):
        path = provenance_dir / filename
        row = provenance.get(filename)
        if not isinstance(row, dict) or row.get("sha256") != sha256_file(path) or row.get("size") != path.stat().st_size:
            raise ComplianceError(f"{manifest_path}: provenance digest differs for {filename}")


def verify_sbom(
    asset_dir: Path,
    packages: Sequence[Package],
    policy: Mapping[str, Any],
    builder_commit: str,
    licenses: Mapping[str, str],
) -> None:
    path = asset_dir / "compliance/sbom.spdx.json"
    document = load_json(path)
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3":
        raise ComplianceError(f"{path}: not an SPDX 2.3 document")
    if document.get("dataLicense") != "CC0-1.0" or document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ComplianceError(f"{path}: invalid document header")
    rows = document.get("packages")
    relationships = document.get("relationships")
    if not isinstance(rows, list) or not isinstance(relationships, list):
        raise ComplianceError(f"{path}: packages/relationships are required")
    by_id = {row.get("SPDXID"): row for row in rows if isinstance(row, dict)}
    required_ids = {"SPDXRef-Package-vm-assets", "SPDXRef-Package-builder", *(package.spdx_id for package in packages)}
    if set(by_id) != required_ids:
        raise ComplianceError(f"{path}: SPDX package set differs from lock")
    if by_id["SPDXRef-Package-builder"].get("versionInfo") != builder_commit:
        raise ComplianceError(f"{path}: builder version differs from binary manifest")
    project_license = str(policy["project_license"])
    builder_row = by_id["SPDXRef-Package-builder"]
    if builder_row.get("licenseConcluded") != project_license or builder_row.get("licenseDeclared") != project_license:
        raise ComplianceError(f"{path}: builder license differs from policy")
    expected_aggregate = aggregate_license_expression([project_license, *licenses.values()])
    aggregate_row = by_id["SPDXRef-Package-vm-assets"]
    if (
        aggregate_row.get("licenseConcluded") != expected_aggregate
        or aggregate_row.get("licenseDeclared") != expected_aggregate
    ):
        raise ComplianceError(f"{path}: aggregate license expression differs from contained packages")
    serialized = canonical_json(document)
    for token in policy.get("forbidden_license_tokens", []):
        if token in serialized:
            raise ComplianceError(f"{path}: forbidden compliance token {token!r}")
    for row in rows:
        if row.get("filesAnalyzed") is not False:
            raise ComplianceError(f"{path}: package filesAnalyzed must be false")
        for key in ("licenseConcluded", "licenseDeclared", "copyrightText"):
            if not isinstance(row.get(key), str) or not row[key]:
                raise ComplianceError(f"{path}: {row.get('SPDXID')}.{key} is empty")
        normalize_license(row["licenseConcluded"], policy)
        normalize_license(row["licenseDeclared"], policy)
    contains = {
        (row.get("spdxElementId"), row.get("relationshipType"), row.get("relatedSpdxElement"))
        for row in relationships
        if isinstance(row, dict)
    }
    for package in packages:
        if ("SPDXRef-Package-vm-assets", "CONTAINS", package.spdx_id) not in contains:
            raise ComplianceError(f"{path}: missing CONTAINS relationship for {package.name}")
        row = by_id[package.spdx_id]
        if row.get("versionInfo") != package.version or row.get("downloadLocation") != package.url:
            raise ComplianceError(f"{path}: package metadata differs for {package.name}")
        checksums = row.get("checksums")
        if checksums != [{"algorithm": "SHA256", "checksumValue": package.sha256}]:
            raise ComplianceError(f"{path}: package checksum differs for {package.name}")
        if (
            row.get("licenseConcluded") != licenses[package.name]
            or row.get("licenseDeclared") != licenses[package.name]
        ):
            raise ComplianceError(f"{path}: package license differs from normalized lock for {package.name}")


def verify_license_evidence(
    asset_dir: Path,
    packages: Sequence[Package],
    policy: Mapping[str, Any],
    licenses: Mapping[str, str],
) -> None:
    license_root = asset_dir / "compliance/licenses"
    expected = {package.origin for package in packages} | {"project"}
    if not license_root.is_dir():
        raise ComplianceError(f"missing license evidence: {license_root}")
    actual = {path.name for path in license_root.iterdir() if path.is_dir()}
    if actual != expected:
        raise ComplianceError(f"license evidence origin set differs; missing={sorted(expected-actual)}, extra={sorted(actual-expected)}")
    evidence: dict[str, list[str]] = {}
    for origin in expected:
        files = [path for path in (license_root / origin).rglob("*") if path.is_file()]
        if not files or any(path.stat().st_size == 0 for path in files):
            raise ComplianceError(f"missing or empty license text for {origin}")
        evidence[origin] = [path.relative_to(license_root).as_posix() for path in sorted(files)]
    notice_path = asset_dir / "compliance/THIRD_PARTY_NOTICES.md"
    source_path = asset_dir / "compliance/SOURCE.md"
    try:
        actual_notice = notice_path.read_text(encoding="utf-8")
        actual_source = source_path.read_text(encoding="utf-8")
    except OSError as error:
        raise ComplianceError(f"cannot read generated compliance documents: {error}") from error
    if actual_notice != make_notices(packages, dict(licenses), evidence, dict(policy)):
        raise ComplianceError(f"{notice_path}: content differs from lock and license evidence")
    if actual_source != make_source_notice(packages):
        raise ComplianceError(f"{source_path}: content differs from locked source provenance")


def verify_zip(asset_dir: Path, archive_path: Path) -> None:
    if not archive_path.is_file():
        raise ComplianceError(f"missing binary archive: {archive_path}")
    expected = {f"vm_assets/{path.relative_to(asset_dir).as_posix()}": path for path in asset_dir.rglob("*") if path.is_file()}
    with zipfile.ZipFile(archive_path) as archive:
        actual_files = {}
        for info in archive.infolist():
            relative = require_relative_path(info.filename, "ZIP entry")
            if not relative.parts or relative.parts[0] != "vm_assets":
                raise ComplianceError(f"ZIP entry is outside vm_assets/: {info.filename}")
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ComplianceError(f"ZIP contains symlink: {info.filename}")
            if not info.is_dir():
                if info.filename in actual_files:
                    raise ComplianceError(f"duplicate ZIP entry: {info.filename}")
                actual_files[info.filename] = info
        if set(actual_files) != set(expected):
            raise ComplianceError("ZIP file inventory differs from build/assets")
        for name, path in expected.items():
            if archive.read(actual_files[name]) != path.read_bytes():
                raise ComplianceError(f"ZIP content differs for {name}")


def extract_source_archive(bundle: Path, destination: Path) -> list[str]:
    zstd = shutil.which("zstd")
    if zstd is None:
        raise ComplianceError("verifying vm_assets-sources.tar.zst requires zstd")
    uncompressed = destination / "source.tar"
    with uncompressed.open("wb") as handle:
        result = subprocess.run(
            [zstd, "-q", "-d", "-c", str(bundle)],
            check=False,
            stdout=handle,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        raise ComplianceError(f"cannot decompress source bundle: {result.stderr.decode(errors='replace').strip()}")
    names: list[str] = []
    symlinks: list[tuple[Path, str, str]] = []
    with tarfile.open(uncompressed, mode="r:") as archive:
        for member in archive.getmembers():
            name = member.name.removesuffix("/")
            if not name:
                continue
            relative = require_relative_path(name, "source archive entry")
            if not relative.parts or relative.parts[0] != "vm_assets-sources":
                raise ComplianceError(f"source archive entry is outside vm_assets-sources/: {name}")
            if name in names:
                raise ComplianceError(f"source archive contains duplicate entry: {name}")
            names.append(name)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise ComplianceError(f"cannot read source archive member: {name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(member.mode & 0o777 or 0o644)
            elif member.issym():
                link_target = member.linkname
                if not link_target or PurePosixPath(link_target).is_absolute():
                    raise ComplianceError(f"unsafe source archive symlink: {name} -> {link_target!r}")
                resolved = posixpath.normpath(posixpath.join(relative.parent.as_posix(), link_target))
                if resolved == ".." or resolved.startswith("../") or not resolved.startswith("vm_assets-sources/"):
                    raise ComplianceError(f"source archive symlink escapes root: {name} -> {link_target!r}")
                symlinks.append((target, link_target, name))
            else:
                raise ComplianceError(f"source archive has unsupported entry type: {name}")
    uncompressed.unlink()
    for target, link_target, name in symlinks:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise ComplianceError(f"source archive symlink collides with another entry: {name}")
        target.symlink_to(link_target)
    return names


def source_channel(package: Package) -> str:
    return "main" if package.role == "kernel" else repository_channel(package.repository)


def verify_source_bundle(
    bundle: Path,
    packages: Sequence[Package],
    lock: Mapping[str, Any],
    binary_manifest: Mapping[str, Any],
) -> None:
    if not bundle.is_file() or bundle.stat().st_size == 0:
        raise ComplianceError(f"missing source bundle: {bundle}")
    with tempfile.TemporaryDirectory(prefix="verify-vm-source-") as temporary:
        extract_source_archive(bundle, Path(temporary))
        root = Path(temporary) / "vm_assets-sources"
        manifest_path = root / "SOURCE_MANIFEST.json"
        manifest = load_json(manifest_path)
        if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
            raise ComplianceError("source bundle manifest has an unsupported schema")
        binary_builder = binary_manifest.get("builder")
        if not isinstance(binary_builder, dict):
            raise ComplianceError("binary manifest has no builder object")
        if manifest.get("builderCommit") != binary_builder.get("commit"):
            raise ComplianceError("source and binary builder commits differ")
        if manifest.get("assetVersion") != binary_manifest.get("assetVersion"):
            raise ComplianceError("source and binary asset versions differ")
        if manifest.get("alpine") != binary_manifest.get("alpine") or manifest.get("alpine") != lock.get("alpine"):
            raise ComplianceError("source, binary, and lock Alpine metadata differ")
        rows = manifest.get("files")
        if not isinstance(rows, list):
            raise ComplianceError("source bundle manifest has no files array")
        declared: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                raise ComplianceError("malformed source manifest row")
            relative = str(require_relative_path(row["path"], "source manifest path"))
            if relative in declared:
                raise ComplianceError(f"source manifest duplicates path {relative}")
            path = root / relative
            row_type = row.get("type", "file")
            if row_type == "file":
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or row.get("mode") != f"{stat.S_IMODE(path.stat().st_mode):04o}"
                    or row.get("sha256") != sha256_file(path)
                    or row.get("size") != path.stat().st_size
                ):
                    raise ComplianceError(f"source manifest differs for {relative}")
            elif row_type == "symlink":
                if not path.is_symlink() or row.get("target") != os.readlink(path):
                    raise ComplianceError(f"source symlink manifest differs for {relative}")
                target = os.readlink(path)
                resolved = posixpath.normpath(posixpath.join(PurePosixPath(relative).parent.as_posix(), target))
                if resolved == ".." or resolved.startswith("../"):
                    raise ComplianceError(f"source manifest symlink escapes root: {relative}")
            else:
                raise ComplianceError(f"source manifest has unsupported entry type {row_type!r}")
            declared[relative] = row
        actual = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if (path.is_file() or path.is_symlink()) and path != manifest_path
        }
        if set(declared) != actual:
            raise ComplianceError("source manifest inventory differs from archive")
        for required in (
            "BUILDING.md",
            "builder/config/packages.lock.json",
            "builder/config/vm-assets.json",
        ):
            if required not in actual:
                raise ComplianceError(f"source bundle is missing {required}")
        bundled_lock = load_json(root / "builder/config/packages.lock.json")
        if bundled_lock != lock:
            raise ComplianceError("builder source contains a dependency lock different from the binary lock")
        bundled_asset_config = load_vm_asset_config(root / "builder/config/vm-assets.json")
        if bundled_asset_config["assetVersion"] != binary_manifest.get("assetVersion"):
            raise ComplianceError("builder source and binary asset versions differ")

        sources = load_json(root / "SOURCES.json")
        if not isinstance(sources, dict) or sources.get("schemaVersion") != 1:
            raise ComplianceError("source bundle SOURCES.json has an unsupported schema")
        if sources.get("builderCommit") != binary_builder.get("commit"):
            raise ComplianceError("SOURCES.json builder commit differs from binary manifest")
        source_rows = sources.get("sources")
        if not isinstance(source_rows, list):
            raise ComplianceError("SOURCES.json sources must be an array")
        rows_by_origin = {}
        for row in source_rows:
            if not isinstance(row, dict) or not isinstance(row.get("origin"), str):
                raise ComplianceError("SOURCES.json contains a malformed source row")
            if row["origin"] in rows_by_origin:
                raise ComplianceError(f"SOURCES.json has duplicate origin {row['origin']}")
            rows_by_origin[row["origin"]] = row
        expected_origins = {package.origin for package in packages}
        if set(rows_by_origin) != expected_origins:
            raise ComplianceError("SOURCES.json origin set differs from the dependency lock")

        packages_by_origin: dict[str, list[Package]] = {}
        for package in packages:
            packages_by_origin.setdefault(package.origin, []).append(package)
        for package in packages:
            channel = source_channel(package)
            recipe_path = root / "aports" / package.aports_commit / channel / package.origin / "APKBUILD"
            if not recipe_path.is_file():
                raise ComplianceError(f"source bundle lacks exact aports recipe for {package.name}: {recipe_path}")
            if package.role == "runtime":
                metadata = f"packages/{package.filename}.PKGINFO"
                digest = f"packages/{package.filename}.sha256"
                if metadata not in actual or digest not in actual:
                    raise ComplianceError(f"source bundle lacks APK evidence for {package.name}")
                fields = parse_pkginfo(root / metadata)
                exact = {
                    "pkgname": package.name,
                    "pkgver": package.version,
                    "origin": package.origin,
                    "license": package.license_expression,
                    "commit": package.aports_commit,
                }
                for field, expected in exact.items():
                    if fields.get(field) != expected:
                        raise ComplianceError(f"source .PKGINFO {package.name}.{field} differs from lock")
                if package.datahash and fields.get("datahash") != package.datahash:
                    raise ComplianceError(f"source .PKGINFO {package.name}.datahash differs from lock")
                checksum_text = (root / digest).read_text(encoding="utf-8")
                if checksum_text != f"{package.sha256}  {package.filename}\n":
                    raise ComplianceError(f"source APK checksum text differs for {package.name}")
            if not any(path.startswith(f"licenses/{package.origin}/") for path in actual):
                raise ComplianceError(f"source bundle lacks license evidence for {package.origin}")

        for origin, origin_packages in sorted(packages_by_origin.items()):
            first = origin_packages[0]
            channel = source_channel(first)
            if any(
                package.aports_commit != first.aports_commit or source_channel(package) != channel
                for package in origin_packages
            ):
                raise ComplianceError(f"origin {origin} maps to multiple aports recipes")
            recipe = root / "aports" / first.aports_commit / channel / origin
            algorithm, expected_checksums = recipe_checksums(recipe / "APKBUILD")
            source_row = rows_by_origin[origin]
            expected_row_header = {
                "packages": sorted(package.name for package in origin_packages),
                "aportsCommit": first.aports_commit,
                "repository": channel,
            }
            for field, expected in expected_row_header.items():
                if source_row.get(field) != expected:
                    raise ComplianceError(f"SOURCES.json {origin}.{field} differs from lock")
            distfile_rows = source_row.get("distfiles")
            if not isinstance(distfile_rows, list):
                raise ComplianceError(f"SOURCES.json {origin}.distfiles must be an array")
            by_name = {}
            for row in distfile_rows:
                if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                    raise ComplianceError(f"SOURCES.json has malformed distfile for {origin}")
                if row["name"] in by_name:
                    raise ComplianceError(f"SOURCES.json duplicates {origin}/{row['name']}")
                by_name[row["name"]] = row
            if set(by_name) != set(expected_checksums):
                raise ComplianceError(f"SOURCES.json distfile set differs from APKBUILD for {origin}")
            for filename, digest in expected_checksums.items():
                row = by_name[filename]
                if row.get(algorithm) != digest:
                    raise ComplianceError(f"SOURCES.json checksum differs for {origin}/{filename}")
                local = recipe / filename
                remote = root / "distfiles" / origin / filename
                if local.is_file():
                    if row.get("kind") != "aports-local" or hash_file(local, algorithm) != digest:
                        raise ComplianceError(f"aports-local source differs for {origin}/{filename}")
                    if remote.exists():
                        raise ComplianceError(f"aports-local source was unexpectedly duplicated as a distfile: {origin}/{filename}")
                else:
                    if row.get("kind") != "upstream-distfile" or not remote.is_file():
                        raise ComplianceError(f"upstream distfile is missing for {origin}/{filename}")
                    if hash_file(remote, algorithm) != digest or row.get("sha256") != sha256_file(remote):
                        raise ComplianceError(f"upstream distfile checksum differs for {origin}/{filename}")
            license_rows = source_row.get("licenseFiles")
            if not isinstance(license_rows, list) or not license_rows:
                raise ComplianceError(f"SOURCES.json lacks license files for {origin}")
            for relative in license_rows:
                if not isinstance(relative, str) or not (root / require_relative_path(relative, "license source row")).is_file():
                    raise ComplianceError(f"SOURCES.json names a missing license file for {origin}: {relative!r}")


def run(arguments: argparse.Namespace) -> None:
    build_dir = arguments.build_dir.resolve()
    asset_dir = (arguments.asset_dir or build_dir / "assets").resolve()
    archive = (arguments.archive or build_dir / "release/vm_assets.zip").resolve()
    lock, packages = load_lock(arguments.lock.resolve())
    repo = arguments.repo.resolve()
    asset_config = load_vm_asset_config(repo / "config/vm-assets.json")
    policy = load_policy(arguments.policy.resolve())
    licenses = {package.name: normalize_license(package.license_expression, policy) for package in packages}

    provenance_dir = build_dir / "provenance"
    validate_package_evidence(packages, provenance_dir / "packages", build_dir / "cache/apks")
    validate_packages_provenance(
        provenance_dir / "packages.json", build_dir, arguments.lock.resolve(), packages
    )
    initramfs = unique_asset(asset_dir, "initramfs-*")
    kernel_image = unique_asset(asset_dir, "Image-*")
    validate_asset_allowlist(asset_dir, kernel_image, initramfs)
    entries = read_newc(initramfs)
    check_initramfs_content(entries)
    verify_mdns_payload(entries, repo)
    file_map = load_file_map(provenance_dir / "file-map.json")
    verify_file_map(entries, file_map, packages)
    iso = find_iso(build_dir, lock["alpine"]["isoUrl"])
    iso_hash = sha256_file(iso)
    if iso_hash != lock["alpine"]["isoSha256"]:
        raise ComplianceError("cached ISO SHA-256 differs from lock")
    validate_kernel_provenance(
        provenance_dir / "kernel.json",
        packages,
        iso_hash,
        lock["alpine"]["isoUrl"],
        kernel_image,
        entries,
        file_map,
    )

    verify_manifest(
        asset_dir,
        lock,
        packages,
        provenance_dir,
        licenses,
        asset_config["assetVersion"],
    )
    binary_manifest = load_json(asset_dir / "manifest.json")
    if not isinstance(binary_manifest, dict):
        raise ComplianceError("binary manifest is not an object")
    builder = binary_manifest.get("builder")
    if not isinstance(builder, dict) or not isinstance(builder.get("commit"), str):
        raise ComplianceError("binary manifest has no builder commit")
    verify_license_evidence(asset_dir, packages, policy, licenses)
    verify_sbom(asset_dir, packages, policy, builder["commit"], licenses)
    verify_checksum_file(asset_dir)
    verify_zip(asset_dir, archive)
    if arguments.source_bundle is not None:
        verify_source_bundle(arguments.source_bundle.resolve(), packages, lock, binary_manifest)
    print(f"Compliance verification passed for {asset_dir}")


def main() -> int:
    try:
        run(parse_arguments())
    except (ComplianceError, OSError, zipfile.BadZipFile) as error:
        print(f"compliance verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
